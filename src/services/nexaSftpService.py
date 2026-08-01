# nexaSftpService.py
# Under the MIT license.
# PLEASE read the Paramiko documentation to get an understanding of
# how the code is written and why design choices were made.


import asyncio
import os
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import paramiko
import pinggy

from services import nexaLoggerFactory
from services.nexaConfig import NexaConfig

logger = nexaLoggerFactory.get_logger("NexaSftpService")
config = NexaConfig("NexaBotConfig.yaml")

def clamp(value, min_val, max_val):
    return max(min_val, min(value, max_val))

sessionTimeoutSecondsConfigEntry = clamp(config.get("security.sftpConnectionLengthInMins", 15), 5, 45)
SESSION_TIMEOUT_SECONDS = sessionTimeoutSecondsConfigEntry * 60
KEY_VALIDITY_POLL_SECONDS = 30  # how often the session checks its own authorization
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT_RANGE = (19000, 19999) 
CLIENT_KEY_BITS = 3072
HOST_KEY_BITS = 3072


@dataclass
class SftpSessionOutcome:
    """
    Final result handed back once an SFTP session ends.
    """
    reason: str  # "client_disconnected", "timeout", "closed_explicitly", "startup_failed"


class _JailedSftpHandle(paramiko.SFTPHandle):
    """
    Thin wrapper around an already-opened file object. Path resolution has already
    happened by the time a handle is created (in the interface's open() method) - this
    class only operates on the real, already-validated file handle it was given.
    """

    def __init__(self, fileObject, flags=0):
        super().__init__(flags)
        self._fileObject = fileObject

    @property
    def readfile(self):
        return self._fileObject

    @property
    def writefile(self):
        return self._fileObject

    def close(self):
        try:
            self._fileObject.close()
        except Exception:
            pass
        return paramiko.SFTP_OK

    def read(self, offset, length):
        try:
            self._fileObject.seek(offset)
            data = self._fileObject.read(length)
            return data
        except Exception as e:
            logger.warning(f"SFTP read error: {e}")
            return paramiko.SFTP_FAILURE

    def write(self, offset, data):
        try:
            self._fileObject.seek(offset)
            self._fileObject.write(data)
            return paramiko.SFTP_OK
        except Exception as e:
            logger.warning(f"SFTP write error: {e}")
            return paramiko.SFTP_FAILURE

    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self._fileObject.fileno()))
        except Exception as e:
            logger.warning(f"SFTP handle stat error: {e}")
            return paramiko.SFTP_FAILURE

    def chattr(self, attr):
        # Attribute changes on open handles are not supported - out of scope for this
        # feature's intended use (transferring/managing modpack and config files).
        return paramiko.SFTP_OP_UNSUPPORTED


class _JailedSftpServerInterface(paramiko.SFTPServerInterface):
    """
    Every method here that touches a path calls self._resolveJailedPath() first, and
    only proceeds if it returns a real, validated, in-jail path. This is the single
    choke point referenced throughout this file's design - do not add a new path-
    touching method without routing it through _resolveJailedPath().
    """

    def __init__(self, server, jailRoot: str, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        # Resolved once at session start - the canonical, symlink-free real path of
        # the instance folder this session is confined to.
        self.jailRoot = os.path.realpath(jailRoot)

    def _resolveJailedPath(self, requestedPath: str) -> Optional[str]:
        """
        The single choke point. Takes whatever path string the SFTP client sent
        (which may be relative, may contain '..', may be a path through a symlink)
        and returns the real, resolved, filesystem path ONLY if it stays inside
        self.jailRoot. Returns None if the path would escape the jail - callers
        must treat None as SFTP_PERMISSION_DENIED, never proceed with it.

        This function must be flawless, and without bugs, to ensure one cannot
        escape the jailed root. PLEASE BE CAREFUL IF YOU MODIFY THIS FUNCTION!
        """
        # SFTP paths are POSIX-style and may be relative to the jail root.
        candidate = requestedPath.lstrip("/")
        joined = os.path.join(self.jailRoot, candidate)
        resolved = os.path.realpath(joined)

        if resolved == self.jailRoot or resolved.startswith(self.jailRoot + os.sep):
            return resolved

        logger.warning(f"SFTP path confinement rejected an out-of-jail request: "
                        f"'{requestedPath}' resolved to '{resolved}', outside jail '{self.jailRoot}'.")
        return None

    def canonicalize(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return "/"
        
        # Return the path relative to the jail root, POSIX-style, as the client expects.
        relative = os.path.relpath(resolved, self.jailRoot)
        return "/" if relative == "." else "/" + relative.replace(os.sep, "/")

    def list_folder(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            entries = []
            for name in os.listdir(resolved):
                fullPath = os.path.join(resolved, name)
                attr = paramiko.SFTPAttributes.from_stat(os.lstat(fullPath))
                attr.filename = name
                entries.append(attr)
            return entries
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except PermissionError:
            return paramiko.SFTP_PERMISSION_DENIED
        except Exception as e:
            logger.warning(f"SFTP list_folder error: {e}")
            return paramiko.SFTP_FAILURE

    def stat(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(resolved))
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.warning(f"SFTP stat error: {e}")
            return paramiko.SFTP_FAILURE

    def lstat(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(resolved))
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.warning(f"SFTP lstat error: {e}")
            return paramiko.SFTP_FAILURE

    def open(self, path, flags, attr):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            pyFlags = os.O_RDONLY
            if flags & os.O_WRONLY:
                pyFlags = os.O_WRONLY
            elif flags & os.O_RDWR:
                pyFlags = os.O_RDWR
            if flags & os.O_APPEND:
                pyFlags |= os.O_APPEND
            if flags & os.O_CREAT:
                pyFlags |= os.O_CREAT
            if flags & os.O_TRUNC:
                pyFlags |= os.O_TRUNC
            if flags & os.O_EXCL:
                pyFlags |= os.O_EXCL

            mode = getattr(attr, "st_mode", 0o644) or 0o644
            fd = os.open(resolved, pyFlags, mode)
            mode_str = "rb+" if (pyFlags & os.O_RDWR) else ("wb" if (pyFlags & os.O_WRONLY) else "rb")
            fileObject = os.fdopen(fd, mode_str)
            return _JailedSftpHandle(fileObject, flags)
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except PermissionError:
            return paramiko.SFTP_PERMISSION_DENIED
        except Exception as e:
            logger.warning(f"SFTP open error: {e}")
            return paramiko.SFTP_FAILURE

    def mkdir(self, path, attr):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            mode = getattr(attr, "st_mode", 0o755) or 0o755
            os.mkdir(resolved, mode)
            return paramiko.SFTP_OK
        except FileExistsError:
            return paramiko.SFTP_FAILURE
        except Exception as e:
            logger.warning(f"SFTP mkdir error: {e}")
            return paramiko.SFTP_FAILURE

    def rmdir(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.rmdir(resolved)
            return paramiko.SFTP_OK
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.warning(f"SFTP rmdir error: {e}")
            return paramiko.SFTP_FAILURE

    def remove(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.remove(resolved)
            return paramiko.SFTP_OK
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.warning(f"SFTP remove error: {e}")
            return paramiko.SFTP_FAILURE

    def rename(self, oldpath, newpath):
        # Both endpoints must independently resolve inside the jail - resolving only
        # one and assuming the other is equally safe is exactly the kind of per-method
        # inconsistency this design is meant to prevent.
        resolvedOld = self._resolveJailedPath(oldpath)
        resolvedNew = self._resolveJailedPath(newpath)
        if resolvedOld is None or resolvedNew is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            if os.path.exists(resolvedNew):
                return paramiko.SFTP_FAILURE  # POSIX sftp rename must not silently overwrite
            os.rename(resolvedOld, resolvedNew)
            return paramiko.SFTP_OK
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.warning(f"SFTP rename error: {e}")
            return paramiko.SFTP_FAILURE

    def posix_rename(self, oldpath, newpath):
        resolvedOld = self._resolveJailedPath(oldpath)
        resolvedNew = self._resolveJailedPath(newpath)
        if resolvedOld is None or resolvedNew is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.replace(resolvedOld, resolvedNew)  # posix_rename permits overwrite
            return paramiko.SFTP_OK
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except Exception as e:
            logger.warning(f"SFTP posix_rename error: {e}")
            return paramiko.SFTP_FAILURE

    def symlink(self, target_path, path):
        # Symlink creation inside the jail is deliberately refused entirely. Even with
        # _resolveJailedPath() confining where the symlink FILE itself can be created,
        # nothing stops its TARGET from pointing outside the jail - and a permissive
        # symlink() is the single easiest way to reintroduce the exact escape this
        # whole design exists to prevent. Not worth the risk for this feature's use case.
        logger.warning("SFTP symlink creation was requested and refused (disabled by design).")
        return paramiko.SFTP_OP_UNSUPPORTED

    def readlink(self, path):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            target = os.readlink(resolved)
            # Only reveal the link if ITS TARGET also resolves inside the jail -
            # otherwise we'd be confirming the existence/location of something outside
            # the jail, which is its own small information leak.
            realTarget = os.path.realpath(target if os.path.isabs(target) else os.path.join(os.path.dirname(resolved), target))
            if realTarget != self.jailRoot and not realTarget.startswith(self.jailRoot + os.sep):
                return paramiko.SFTP_PERMISSION_DENIED
            return target
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE
        except OSError:
            return paramiko.SFTP_FAILURE
        except Exception as e:
            logger.warning(f"SFTP readlink error: {e}")
            return paramiko.SFTP_FAILURE

    def chattr(self, path, attr):
        resolved = self._resolveJailedPath(path)
        if resolved is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            if getattr(attr, "st_mode", None) is not None:
                os.chmod(resolved, attr.st_mode)
            return paramiko.SFTP_OK
        except Exception as e:
            logger.warning(f"SFTP chattr error: {e}")
            return paramiko.SFTP_FAILURE

    def session_started(self):
        pass

    def session_ended(self):
        pass


class _SingleKeyServerInterface(paramiko.ServerInterface):
    """
    Authenticates exactly one public key (the ephemeral client key generated for this
    session) and permits exactly one thing after auth: opening the sftp subsystem.
    Everything else (shell, exec, port forwarding, etc.) is refused.
    """

    def __init__(self, expectedPublicKey: paramiko.PKey):
        super().__init__()
        self._expectedPublicKey = expectedPublicKey
        self._authEvent = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        matches = (
            key.get_name() == self._expectedPublicKey.get_name()
            and key.asbytes() == self._expectedPublicKey.asbytes()
        )
        logger.info(f"SFTP public key auth attempt (username='{username}', "
                    f"key_type={key.get_name()}): {'accepted' if matches else 'rejected'}")
        if matches:
            self._authEvent.set()
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        return False

    def check_channel_exec_request(self, channel, command):
        return False

    def check_channel_pty_request(self, *args, **kwargs):
        return False

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port):
        return False


class SftpSession:
    """
    One-shot SFTP session: owns the TCP listener, the Pinggy tunnel, the ephemeral
    host key and client keypair, and the timeout state machine. Never reused.
    """

    def __init__(self, jailRoot: str, discordUserID: int, authService=None):
        self.jailRoot = jailRoot
        self.discordUserID = discordUserID
        self.authService = authService

        self.localPort: Optional[int] = None
        self.tunnelHost: Optional[str] = None
        self.tunnelPort: Optional[int] = None
        self.privateKeyPem: Optional[str] = None

        self._hostKey: Optional[paramiko.RSAKey] = None
        self._clientPublicKey: Optional[paramiko.RSAKey] = None
        self._tunnel: Optional["pinggy.Tunnel"] = None
        self._listenerSocket: Optional[socket.socket] = None
        self._listenerThread: Optional[threading.Thread] = None
        self._stopEvent = threading.Event()

        self._loop = asyncio.get_event_loop()
        self._outcomeFuture: "asyncio.Future[SftpSessionOutcome]" = self._loop.create_future()
        self._resolved = False
        self._timeoutTask: Optional[asyncio.Task] = None
        self._keyValidityTask: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._hostKey = paramiko.RSAKey.generate(HOST_KEY_BITS)
        clientKey = paramiko.RSAKey.generate(CLIENT_KEY_BITS)
        self._clientPublicKey = clientKey

        import io
        pemBuffer = io.StringIO()
        clientKey.write_private_key(pemBuffer)
        self.privateKeyPem = pemBuffer.getvalue()

        self.localPort = self._pickLocalPort()

        self._listenerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listenerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listenerSocket.bind((LOCAL_HOST, self.localPort))
        self._listenerSocket.listen(5)  # backlog for a few near-simultaneous connections
        # from the same client (e.g. a listing connection plus a separate transfer
        # connection opened moments later) - NOT a cap on total connections over the
        # session's lifetime, which is unbounded and governed only by the timeout.

        self._listenerThread = threading.Thread(target=self._acceptLoop, daemon=True)
        self._listenerThread.start()

        self._tunnel = pinggy.Tunnel()
        self._tunnel.add_forwarding(f"{LOCAL_HOST}:{self.localPort}", type="tcp")
        self._tunnel.start(thread=True)

        for _ in range(50):
            if self._tunnel.urls:
                break
            await asyncio.sleep(0.1)

        if not self._tunnel.urls:
            await self._teardown()
            raise RuntimeError("Pinggy tunnel failed to establish for SFTP session.")

        # TCP tunnels from Pinggy expose a host:port pair rather than an https:// URL.
        tunnelUrl = self._tunnel.urls[0]
        self.tunnelHost, portStr = tunnelUrl.replace("tcp://", "").rsplit(":", 1)
        self.tunnelPort = int(portStr)

        logger.info(f"SFTP session started for Discord user {self.discordUserID}. "
                    f"Jail root: {self.jailRoot}. Tunnel: {self.tunnelHost}:{self.tunnelPort}")

        self._timeoutTask = asyncio.create_task(self._timeoutWatcher())

        if self.authService is not None:
            self._keyValidityTask = asyncio.create_task(self._keyValidityWatcher())
        else:
            logger.warning(f"SFTP session for Discord user {self.discordUserID} started with no "
                            f"authService reference - key validity polling is disabled for this "
                            f"session. Explicit revoke-triggered stop still works if wired "
                            f"externally, but the self-checking watchdog will not run.")

    def _acceptLoop(self) -> None:
        """
        Runs in a background thread for the full lifetime of the session. Accepts and
        handles connections continuously until the session ends (timeout or explicit
        close) - NOT limited to a single TCP connection.

        This matters because real SFTP clients (FileZilla among them) commonly open
        more than one connection per logical session for a parallel operation that
        opens multiple connections.
        """
        try:
            self._listenerSocket.settimeout(1.0)
            connectionCount = 0
            while not self._stopEvent.is_set():
                try:
                    clientSocket, addr = self._listenerSocket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return

                connectionCount += 1
                logger.info(f"SFTP connection #{connectionCount} accepted from {addr} "
                            f"for Discord user {self.discordUserID}'s session.")

                handlerThread = threading.Thread(
                    target=self._handleConnection,
                    args=(clientSocket,),
                    daemon=True
                )
                handlerThread.start()

        except Exception as e:
            logger.warning(f"SFTP accept loop error: {e}")
            self._scheduleResolve(SftpSessionOutcome(reason="startup_failed"))

    def _handleConnection(self, clientSocket: socket.socket) -> None:
        """
        Handles exactly one TCP connection's full SSH/SFTP lifecycle: negotiation,
        auth (against the same single ephemeral client key every connection in this
        session must present), channel accept, and blocking until that connection's
        client disconnects. Multiple connections run this concurrently, each in its
        own thread, for the same session.
        """
        try:
            transport = paramiko.Transport(clientSocket)
            transport.add_server_key(self._hostKey)
            transport.set_subsystem_handler(
                "sftp", paramiko.SFTPServer,
                sftp_si=lambda server: _JailedSftpServerInterface(server, self.jailRoot)
            )

            serverInterface = _SingleKeyServerInterface(self._clientPublicKey)

            try:
                transport.start_server(server=serverInterface)
            except paramiko.SSHException as e:
                logger.warning(f"SFTP transport negotiation failed on one connection: {e}")
                transport.close()
                return

            channel = transport.accept(20)
            if channel is None:
                logger.warning("SFTP client authenticated but never opened a channel "
                                "on one connection.")
                transport.close()
                return

            # Block here until THIS connection's client disconnects. The session as
            # a whole keeps running (other connections, or future ones, are
            # unaffected) - only the timeout watcher or an explicit close ends the
            # session itself.
            while transport.is_active() and not self._stopEvent.is_set():
                threading.Event().wait(0.5)

            transport.close()

        except Exception as e:
            logger.warning(f"SFTP connection handler error: {e}")

    def _scheduleResolve(self, outcome: SftpSessionOutcome) -> None:
        # Called from the background accept thread - must hop back onto the event
        # loop rather than touching asyncio primitives directly from another thread.
        self._loop.call_soon_threadsafe(self._resolve, outcome)

    def _resolve(self, outcome: SftpSessionOutcome) -> None:
        if self._resolved:
            return
        self._resolved = True
        if self._timeoutTask and not self._timeoutTask.done():
            self._timeoutTask.cancel()
        if self._keyValidityTask and not self._keyValidityTask.done():
            self._keyValidityTask.cancel()
        if not self._outcomeFuture.done():
            self._outcomeFuture.set_result(outcome)

    async def _timeoutWatcher(self) -> None:
        try:
            await asyncio.sleep(SESSION_TIMEOUT_SECONDS)
            if not self._resolved:
                logger.info(f"SFTP session for Discord user {self.discordUserID} timed out.")
                self._resolve(SftpSessionOutcome(reason="timeout"))
        except asyncio.CancelledError:
            pass

    async def _keyValidityWatcher(self) -> None:
        """
        Periodically re-checks whether self.discordUserID's operator key still
        carries the fsaccess capability. While /fsaccess does hook to a guarded
        event, this serves as additional redundancy, in case.
        """
        try:
            while not self._resolved:
                await asyncio.sleep(KEY_VALIDITY_POLL_SECONDS)
                if self._resolved:
                    break

                entries = self.authService.listOperatorKeys(discordUserID=self.discordUserID)
                stillAuthorized = bool(entries) and "fsaccess" in entries[0].get("capabilities", [])

                if not stillAuthorized:
                    logger.warning(f"SFTP session for Discord user {self.discordUserID} failed a "
                                    f"key validity check - fsaccess is no longer authorized for "
                                    f"this operator. Tearing down.")
                    self._resolve(SftpSessionOutcome(reason="key_invalidated"))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Key validity check failed for Discord user {self.discordUserID}'s "
                         f"SFTP session (session continues; will retry next interval): {e}")

    async def waitForCompletion(self) -> SftpSessionOutcome:
        try:
            outcome = await self._outcomeFuture
        finally:
            await self._teardown()
        return outcome

    async def closeExplicitly(self) -> None:
        """
        Allows the /fsaccess command to force-close a session early (e.g. operator
        confirms they're done, or a head operator wants to kill it).
        """
        self._resolve(SftpSessionOutcome(reason="closed_explicitly"))
        await self.waitForCompletion()

    @staticmethod
    def _pickLocalPort() -> int:
        import secrets
        return secrets.randbelow(LOCAL_PORT_RANGE[1] - LOCAL_PORT_RANGE[0]) + LOCAL_PORT_RANGE[0]

    async def _teardown(self) -> None:
        self._stopEvent.set()

        if self._tunnel is not None:
            try:
                self._tunnel.stop()
            except Exception as e:
                logger.warning(f"Error stopping Pinggy tunnel: {e}")
            self._tunnel = None

        if self._listenerSocket is not None:
            try:
                self._listenerSocket.close()
            except Exception as e:
                logger.warning(f"Error closing SFTP listener socket: {e}")
            self._listenerSocket = None

        # Private key material should not linger in memory longer than necessary.
        self.privateKeyPem = None
        self._clientPublicKey = None
        self._hostKey = None

        logger.info(f"SFTP session for Discord user {self.discordUserID} torn down.")


class NexaSftpService:
    """
    Owns the single-session-at-a-time constraint across all /fsaccess SFTP grants.
    Mirrors NexaVerifService's structure and constraint.
    """

    def __init__(self, authService=None):
        """
        authService: optional NexaAuthenticationService reference, passed through
        to every SftpSession this creates so each session can run its own
        key-validity watchdog (see SftpSession's docstring). If not provided,
        sessions still work but without that self-checking behavior - only an
        explicit closeExplicitly() call (e.g. from an emergency-stop path wired
        externally) will end a session early.
        """
        self.authService = authService
        self._activeSession: Optional[SftpSession] = None
        self._lock = asyncio.Lock()

    async def beginSession(self, jailRoot: str, discordUserID: int) -> SftpSession:
        async with self._lock:
            if self._activeSession is not None:
                raise RuntimeError(
                    "An SFTP session is already active. Only one session is "
                    "permitted at a time."
                )

            resolvedJailRoot = os.path.realpath(jailRoot)
            if not os.path.isdir(resolvedJailRoot):
                raise ValueError(f"Jail root '{resolvedJailRoot}' does not exist or is not a directory.")

            session = SftpSession(resolvedJailRoot, discordUserID, authService=self.authService)
            await session.start()
            self._activeSession = session
            return session

    async def endSession(self, session: SftpSession) -> SftpSessionOutcome:
        try:
            return await session.waitForCompletion()
        finally:
            async with self._lock:
                if self._activeSession is session:
                    self._activeSession = None