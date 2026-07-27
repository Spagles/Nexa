# nexaVerifService.py
# Under the MIT License.

# Spins up a lightweight web authenticator.

import asyncio
import base64
import io
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from aiohttp import web
import qrcode
import pinggy

from services.nexaAuthenticationService import NexaAuthenticationService
from services import nexaLoggerFactory

logger = nexaLoggerFactory.get_logger("NexaVerifService")



# ----------------------------------------------------------------------
# Result / state types
# ----------------------------------------------------------------------

class SessionState:
    INCOMPLETE = "incomplete"
    CONFIRMED = "confirmed"
    FAILED = "failed"


@dataclass
class AuthSessionResult:
    """
    Final result handed back to the /fsaccess command once a session resolves.
    """
    success: bool
    state: str  # SessionState.CONFIRMED or SessionState.FAILED
    reason: str  # "confirmed", "max_attempts_exceeded", "timeout_no_connection", "timeout_after_connection"
    discordUserID: Optional[int] = None
    capabilities: list = field(default_factory=list)


# ----------------------------------------------------------------------
# Timeout constants
# ----------------------------------------------------------------------

IDLE_TIMEOUT_SECONDS = 90          # before any browser connects
CONNECTED_TIMEOUT_SECONDS = 180    # after first connection (3 minutes)
MAX_ATTEMPTS = 2

# Grace period between a session resolving and teardown actually starting.
TEARDOWN_GRACE_SECONDS = 1.5

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT_RANGE = (18000, 18999)  # arbitrary local range, picked to avoid common conflicts



MAX_CONSECUTIVE_FAILED_SESSIONS_BEFORE_BLOCK = 3

_ipConsecutiveFailures: dict = {}   # ip (str) -> consecutive failed-session count
_blockedIPs: set = set()            # ip (str) -> permanently blocked for this process's lifetime


def _recordSessionOutcomeForIP(ip: Optional[str], succeeded: bool) -> None:
    """
    Updates the consecutive-failure streak for one IP based on how a session
    resolved. A None ip (couldn't be determined - e.g. xff header missing) is
    silently ignored rather than tracked under a shared/fake key, since grouping
    unknown-origin traffic together would let one real attacker's failures block
    unrelated legitimate operators whose IP simply couldn't be read.
    """
    if ip is None:
        return

    if succeeded:
        _ipConsecutiveFailures.pop(ip, None)
        return

    count = _ipConsecutiveFailures.get(ip, 0) + 1
    _ipConsecutiveFailures[ip] = count

    if count >= MAX_CONSECUTIVE_FAILED_SESSIONS_BEFORE_BLOCK:
        _blockedIPs.add(ip)
        logger.warning(f"IP {ip} has been blocked for the remainder of this Nexa process "
                        f"after {count} consecutive failed authentication sessions.")


def _isIPBlocked(ip: Optional[str]) -> bool:
    if ip is None:
        return False
    return ip in _blockedIPs


_ipSessionStartTimestamps: dict = {}  # ip (str) -> list[float] of session-start unix timestamps

def _recordSessionStartForShadyDetection(ip: Optional[str], windowSeconds: int) -> list:
    """
    Records a session start for this IP and returns the list of timestamps still
    within the rolling window, pruning anything older. Callers check
    len(returned list) against the configured threshold.
    """
    import time
    if ip is None:
        return []

    now = time.time()
    timestamps = _ipSessionStartTimestamps.setdefault(ip, [])
    timestamps.append(now)

    cutoff = now - windowSeconds
    prunedTimestamps = [t for t in timestamps if t >= cutoff]
    _ipSessionStartTimestamps[ip] = prunedTimestamps

    return prunedTimestamps


class AuthSession:
    """
    Represents a single, one-shot verification session. Owns the aiohttp server,
    the Pinggy tunnel, and the timeout/attempt state machine.

    """

    def __init__(
        self,
        authService: NexaAuthenticationService,
        expectedDiscordUserID: int,
        isHOVerif: bool = False,
    ):
        self.authService = authService
        self.expectedDiscordUserID = expectedDiscordUserID
        self.isHOVerif = isHOVerif

        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._tunnel: Optional["pinggy.Tunnel"] = None

        self.localPort: Optional[int] = None
        self.tunnelUrl: Optional[str] = None
        self.qrCodeDataUri: Optional[str] = None

        self._hasConnected = False
        self._originIP: Optional[str] = None
        self._attemptsUsed = 0
        self._resultFuture: "asyncio.Future[AuthSessionResult]" = asyncio.get_event_loop().create_future()
        self._timeoutTask: Optional[asyncio.Task] = None
        self._resolved = False

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Starts the local aiohttp server and the Pinggy tunnel pointed at it.
        After this returns, self.tunnelUrl and self.qrCodeDataUri are populated
        and ready to hand off (e.g. posted into a Discord embed).
        """
        self._app = web.Application()
        self._app.router.add_get("/", self._handleIndex)
        self._app.router.add_post("/verify", self._handleVerify)

        self.localPort = self._pickLocalPort()

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, LOCAL_HOST, self.localPort)
        await self._site.start()

        self._tunnel = pinggy.Tunnel()
        self._tunnel.add_forwarding(f"{LOCAL_HOST}:{self.localPort}", type="http")
        # Pinggy does NOT forward X-Forwarded-For by default.

        self._tunnel.xff = True
        self._tunnel.start(thread=True)

        # Tunnel establishment is effectively synchronous by the time start() returns
        # for the Python SDK's thread mode, but urls can briefly be empty right after
        # start() fires.
        for _ in range(50):
            if self._tunnel.urls:
                break
            await asyncio.sleep(0.1)

        httpsUrls = [u for u in (self._tunnel.urls or []) if u.startswith("https://")]
        self.tunnelUrl = httpsUrls[0] if httpsUrls else (self._tunnel.urls[0] if self._tunnel.urls else None)

        if not self.tunnelUrl:
            await self._teardown()
            raise RuntimeError("Pinggy tunnel failed to establish a public URL.")

        self.qrCodeDataUri = self._buildQrDataUri(self.tunnelUrl)

        logger.info(f"Auth session started. Tunnel URL: {self.tunnelUrl} (local port {self.localPort})")

        self._timeoutTask = asyncio.create_task(self._idleTimeoutWatcher())

    async def waitForCompletion(self) -> AuthSessionResult:
        """
        Blocks until the session resolves (Confirmed or Failed), waits a short grace
        period so the resolving request's own HTTP response can finish flushing back
        through the tunnel, then tears down the tunnel and local server.
        """
        try:
            result = await self._resultFuture
            await asyncio.sleep(TEARDOWN_GRACE_SECONDS)
        finally:
            await self._teardown()
        return result

    # ------------------------------------------------------------------
    # Internal: timeout state machine
    # ------------------------------------------------------------------

    async def _idleTimeoutWatcher(self) -> None:
        try:
            await asyncio.sleep(IDLE_TIMEOUT_SECONDS)
            if not self._hasConnected and not self._resolved:
                logger.info("Auth session timed out with no browser connection.")
                self._resolve(AuthSessionResult(
                    success=False,
                    state=SessionState.FAILED,
                    reason="timeout_no_connection"
                ))
        except asyncio.CancelledError:
            pass

    def _onFirstConnection(self) -> None:
        if self._hasConnected:
            return
        self._hasConnected = True

        if self._timeoutTask and not self._timeoutTask.done():
            self._timeoutTask.cancel()

        self._timeoutTask = asyncio.create_task(self._connectedTimeoutWatcher())
        logger.info("Browser connected to auth session. Timeout window extended to "
                    f"{CONNECTED_TIMEOUT_SECONDS}s with {MAX_ATTEMPTS} attempts allowed.")

    async def _connectedTimeoutWatcher(self) -> None:
        try:
            await asyncio.sleep(CONNECTED_TIMEOUT_SECONDS)
            if not self._resolved:
                logger.info("Auth session timed out after connection with no valid code submitted.")
                self._resolve(AuthSessionResult(
                    success=False,
                    state=SessionState.FAILED,
                    reason="timeout_after_connection"
                ))
        except asyncio.CancelledError:
            pass

    def _resolve(self, result: AuthSessionResult) -> None:
        if self._resolved:
            return
        self._resolved = True
        if self._timeoutTask and not self._timeoutTask.done():
            self._timeoutTask.cancel()
        if not self._resultFuture.done():
            self._resultFuture.set_result(result)

        # Single choke point for IP outcome recording - every resolution path
        # (success, max attempts, either timeout) funnels through here, so this
        # is the one place this needs to be called rather than at each
        # individual resolve() call site.
        _recordSessionOutcomeForIP(self._originIP, result.success)

    # ------------------------------------------------------------------
    # Internal: HTTP handlers
    # ------------------------------------------------------------------

    @staticmethod
    def _extractClientIP(request: web.Request) -> Optional[str]:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.remote:
            return request.remote
        return None

    async def _handleIndex(self, request: web.Request) -> web.Response:
        clientIP = self._extractClientIP(request)

        if _isIPBlocked(clientIP):
            logger.warning(f"Blocked IP {clientIP} attempted to access an auth session page.")
            return web.Response(
                text="<!DOCTYPE html><html><body style=\"background:#14171c;color:#e6e9ef;"
                     "font-family:sans-serif;text-align:center;padding-top:100px;\">"
                     "<h1>Access Denied</h1></body></html>",
                content_type="text/html",
                status=403
            )

        if self._originIP is None:
            self._originIP = clientIP
            windowSeconds = self._getShadyActivityWindowSeconds()
            threshold = self._getShadyActivityThreshold()
            recentTimestamps = _recordSessionStartForShadyDetection(clientIP, windowSeconds)
            if clientIP is not None and len(recentTimestamps) >= threshold:
                await self._flagShadyActivity(clientIP, len(recentTimestamps), windowSeconds)

        self._onFirstConnection()
        return web.Response(text=_renderPage(state=SessionState.INCOMPLETE), content_type="text/html")

    # Real codes (Head Operator key or operator codes) are always short.
    # Anything longer is either a mistake or a probe, and rejecting it
    # here costs nothing. Simply designed to defend against a resource exhaustion attack.
    MAX_CODE_SUBMISSION_LENGTH = 256

    async def _handleVerify(self, request: web.Request) -> web.Response:
        if self._resolved:
            return web.json_response({"state": SessionState.FAILED, "message": "This session has already ended."})

        try:
            body = await request.json()
            candidateCode = str(body.get("code", "")).strip()
        except Exception:
            return web.json_response({"state": SessionState.INCOMPLETE, "message": "Malformed request."}, status=400)

        if not candidateCode:
            return web.json_response({"state": SessionState.INCOMPLETE, "message": "No code provided."}, status=400)

        if len(candidateCode) > self.MAX_CODE_SUBMISSION_LENGTH:
            logger.warning(f"Auth session received an oversized code submission "
                            f"({len(candidateCode)} chars) - rejected before hashing.")
            return web.json_response(
                {"state": SessionState.INCOMPLETE, "message": "Invalid code."}, status=400
            )

        if self.isHOVerif:
            identityMatches = self.authService.verifyKey(candidateCode)
            if identityMatches:
                logger.info(f"Head Operator root-key auth session confirmed for "
                            f"Discord user {self.expectedDiscordUserID}.")
                self._resolve(AuthSessionResult(
                    success=True,
                    state=SessionState.CONFIRMED,
                    reason="confirmed",
                    discordUserID=self.expectedDiscordUserID,
                    capabilities=[],  # root key carries no /keyman-style capability list
                ))
                return web.json_response({"state": SessionState.CONFIRMED})
        else:
            matchedEntry = self.authService.verifyOperatorKey(candidateCode)

            # A code that's valid but belongs to someone other than the operator who invoked
            # this session is treated identically to an invalid code below - both in the
            # response given to the browser and in that it consumes an attempt. Telling the
            # submitter "that's a real code, just not yours" would confirm a stranger's code
            # is valid, which is an information leak this system shouldn't produce.
            identityMatches = (
                matchedEntry is not None
                and matchedEntry["discordUserID"] == self.expectedDiscordUserID
            )

            if identityMatches:
                logger.info(f"Auth session confirmed for Discord user {matchedEntry['discordUserID']}.")
                self._resolve(AuthSessionResult(
                    success=True,
                    state=SessionState.CONFIRMED,
                    reason="confirmed",
                    discordUserID=matchedEntry["discordUserID"],
                    capabilities=matchedEntry["capabilities"],
                ))
                return web.json_response({"state": SessionState.CONFIRMED})

            if matchedEntry is not None:
                logger.warning(
                    f"Auth session received a valid code belonging to Discord user "
                    f"{matchedEntry['discordUserID']}, but this session expects "
                    f"{self.expectedDiscordUserID}. Treated as a failed attempt."
                )

        self._attemptsUsed += 1
        attemptsRemaining = MAX_ATTEMPTS - self._attemptsUsed

        if attemptsRemaining <= 0:
            logger.warning("Auth session failed: maximum incorrect attempts reached.")
            self._resolve(AuthSessionResult(
                success=False,
                state=SessionState.FAILED,
                reason="max_attempts_exceeded"
            ))
            return web.json_response({"state": SessionState.FAILED, "message": "Too many incorrect attempts."})

        return web.json_response({
            "state": SessionState.INCOMPLETE,
            "message": "Incorrect code.",
            "attemptsRemaining": attemptsRemaining
        })

    # ------------------------------------------------------------------
    # Internal: shady-activity config + notification
    # ------------------------------------------------------------------

    def _getShadyActivityThreshold(self) -> int:
        """
        Reads security.shadyAuthAttemptThreshold from the pinned config on
        self.authService.config (passed in at NexaAuthenticationService construction
        time, not re-read from disk here - see that class's docstring for why).
        """
        config = self.authService.config
        return config.get("security.shadyAuthAttemptThreshold", 10)

    def _getShadyActivityWindowSeconds(self) -> int:
        # Fixed at 60 minutes per design - not currently config-driven, only the
        # threshold count is. Kept as its own method rather than a bare constant
        # reference so a config-driven window could be added later without
        # touching call sites.
        return 60 * 60

    async def _flagShadyActivity(self, ip: str, sessionCountInWindow: int, windowSeconds: int) -> None:
        """
        Fires when one IP's session-start count within the rolling window meets or
        exceeds the configured threshold. Notifies the Head Operator and all Server
        Operators via authService.notifier, if one is configured - otherwise logs
        only, matching NexaAuthenticationService's own notifier-optional pattern.
        """
        message = (
            f"Unusual authentication activity detected: IP `{ip}` has started "
            f"{sessionCountInWindow} verification sessions within the last "
            f"{windowSeconds // 60} minutes (threshold: "
            f"{self._getShadyActivityThreshold()}). This may indicate repeated "
            f"probing against the web authentication layer."
        )
        logger.warning(message)

        notifier = self.authService.notifier
        if notifier is not None and hasattr(notifier, "dmAllOperators"):
            await notifier.dmAllOperators(message)
        else:
            logger.warning("No notifier configured (or notifier lacks dmAllOperators) - "
                            "shady activity was only logged, not delivered to operators.")

    # ------------------------------------------------------------------
    # Internal: helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pickLocalPort() -> int:
        # Simple random pick within a defined local range. Not guaranteed collision-free
        # under concurrent use, but NexaVerifService enforces single-session-at-a-time,
        # so this is fine for the current design.
        return secrets.randbelow(LOCAL_PORT_RANGE[1] - LOCAL_PORT_RANGE[0]) + LOCAL_PORT_RANGE[0]

    @staticmethod
    def _buildQrDataUri(url: str) -> str:
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"

    async def _teardown(self) -> None:
        """
        Unconditional cleanup. Called from waitForCompletion()'s finally block,
        so it always runs regardless of how the session resolved.
        """
        if self._timeoutTask and not self._timeoutTask.done():
            self._timeoutTask.cancel()

        if self._tunnel is not None:
            try:
                self._tunnel.stop()
            except Exception as e:
                logger.warning(f"Error stopping Pinggy tunnel: {e}")
            self._tunnel = None

        if self._site is not None:
            try:
                await self._site.stop()
            except Exception as e:
                logger.warning(f"Error stopping local site: {e}")

        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception as e:
                logger.warning(f"Error cleaning up aiohttp runner: {e}")

        logger.info("Auth session torn down (tunnel + local server stopped).")


class NexaVerifService:
    """
    Owns the single-session-at-a-time constraint across all /fsaccess invocations.
    Only one AuthSession may be active at once, globally.
    """

    def __init__(self, authService: NexaAuthenticationService):
        self.authService = authService
        self._activeSession: Optional[AuthSession] = None
        self._lock = asyncio.Lock()

    async def beginAuthentication(self, discordUserID: int, isHOVerif: bool = False) -> AuthSession:
        """
        Starts a new authentication session scoped to the invoking operator. Only a
        code belonging to discordUserID will be accepted by this session - a valid
        code belonging to any other operator is rejected the same way an invalid
        code would be. Raises RuntimeError if a session is already active - enforces
        the "one exposed access at a time, ever" constraint.

        isHOVerif: pass True to verify against the Head Operator's root credential
        instead of an operator code (used only by /keyman's ticket-renewal flow).
        """
        async with self._lock:
            if self._activeSession is not None:
                raise RuntimeError(
                    "An authentication session is already active. Only one session "
                    "is permitted at a time."
                )

            session = AuthSession(self.authService, expectedDiscordUserID=discordUserID, isHOVerif=isHOVerif)
            await session.start()
            self._activeSession = session
            return session

    async def endSession(self, session: AuthSession) -> AuthSessionResult:
        """
        Convenience wrapper: waits for the given session to complete, then clears
        the active-session slot so a new one may begin.
        """
        try:
            result = await session.waitForCompletion()
            return result
        finally:
            async with self._lock:
                if self._activeSession is session:
                    self._activeSession = None


# ----------------------------------------------------------------------
# Page rendering
# ----------------------------------------------------------------------

def _renderPage(state: str) -> str:
    """
    Renders the single-page auth UI. State is only used for the initial server-side
    render (always INCOMPLETE on first load) - subsequent Confirmed/Failed states
    are driven client-side by JS based on the /verify response, per design.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nexa Authentication</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600&display=swap" rel="stylesheet">
<style>
{_PAGE_CSS}
</style>
</head>
<body>
<div class="auth-card" id="authCard">
  <h1 id="authTitle">Nexa needs to verify you</h1>
  <p id="authSubtext">Submit your authentication code<br>in the textbox below.</p>

  <div id="formArea">
    <input type="text" id="codeInput" placeholder="XXXX-XXXX-XXXX-XXXX or another format..." autocomplete="off" autocapitalize="characters" spellcheck="false">
    <button id="submitBtn">Submit</button>
    <p id="feedbackText" class="feedback"></p>
  </div>

  <div id="resultIcon" class="result-icon" style="display:none;"></div>
</div>

<script>
{_PAGE_JS}
</script>
</body>
</html>"""


_PAGE_CSS = """
:root {
  --bg: #14171c;
  --surface-1: #1b1f26;
  --surface-2: #21262f;
  --border: #2c323d;
  --border-strong: #3a4250;
  --text-primary: #e6e9ef;
  --text-secondary: #9aa3b2;
  --text-muted: #6b7280;
  --accent-blue: #4b8fd9;
  --accent-blue-dim: #2c4a6e;
  --accent-green: #5cba8a;
  --accent-green-dim: #2c4a3c;
  --accent-red: #d96b6b;
  --accent-red-dim: #6e2c2c;
  --shadow-color: 0, 0, 0;
  --radius-lg: 12px;
  --radius-sm: 8px;
  --dur: 180ms;
  --ease: cubic-bezier(0.2, 0, 0, 1);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text-primary);
  font-family: "Montserrat", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  line-height: 1.6;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}

.auth-card {
  width: 100%;
  max-width: 420px;
  text-align: center;
}

.auth-card h1 {
  font-size: 28px;
  font-weight: 500;
  margin: 0 0 12px;
  letter-spacing: -0.01em;
}

.auth-card p {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0 0 24px;
}

#codeInput {
  width: 100%;
  padding: 12px 14px;
  margin-bottom: 14px;
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-family: inherit;
  font-size: 15px;
  text-align: center;
  letter-spacing: 0.04em;
  transition: border-color var(--dur) var(--ease);
}

#codeInput::placeholder { color: var(--text-muted); }

#codeInput:focus {
  outline: none;
  border-color: var(--border-strong);
}

#submitBtn {
  width: 100%;
  font-size: 14px;
  font-weight: 500;
  padding: 12px;
  background: var(--accent-blue-dim);
  border: 1px solid var(--accent-blue);
  border-radius: var(--radius-sm);
  color: var(--accent-blue);
  cursor: pointer;
  transition: background var(--dur) var(--ease), color var(--dur) var(--ease), transform var(--dur) var(--ease);
}

#submitBtn:hover:not(:disabled) {
  background: var(--accent-blue);
  color: var(--bg);
  transform: scale(1.02);
}

#submitBtn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.feedback {
  min-height: 20px;
  font-size: 13px !important;
  margin: 14px 0 0 !important;
  color: var(--accent-red) !important;
}

.feedback.success {
  color: var(--accent-green) !important;
}

.result-icon {
  font-size: 48px;
  margin-top: 8px;
}
"""

_PAGE_JS = """
const codeInput = document.getElementById('codeInput');
const submitBtn = document.getElementById('submitBtn');
const feedbackText = document.getElementById('feedbackText');
const authTitle = document.getElementById('authTitle');
const authSubtext = document.getElementById('authSubtext');
const formArea = document.getElementById('formArea');
const resultIcon = document.getElementById('resultIcon');

function lockForm() {
  codeInput.disabled = true;
  submitBtn.disabled = true;
}

function showConfirmed() {
  authTitle.textContent = 'Confirmed!';
  authSubtext.textContent = 'You have been successfully verified. You may close this page.';
  formArea.style.display = 'none';
  resultIcon.style.display = 'block';
  resultIcon.textContent = '\\u2713';
  resultIcon.style.color = 'var(--accent-green)';
}

function showFailed(message) {
  authTitle.textContent = 'Verification Failed';
  authSubtext.textContent = message || 'This authentication session has ended.';
  formArea.style.display = 'none';
  resultIcon.style.display = 'block';
  resultIcon.textContent = '\\u2715';
  resultIcon.style.color = 'var(--accent-red)';
}

async function submitCode() {
  const code = codeInput.value.trim();
  if (!code) return;

  submitBtn.disabled = true;
  feedbackText.textContent = '';
  feedbackText.classList.remove('success');

  try {
    const response = await fetch('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    const data = await response.json();

    if (data.state === 'confirmed') {
      lockForm();
      showConfirmed();
      return;
    }

    if (data.state === 'failed') {
      lockForm();
      showFailed(data.message);
      return;
    }

    feedbackText.textContent = data.message +
      (typeof data.attemptsRemaining === 'number' ? ' Attempts remaining: ' + data.attemptsRemaining + '.' : '');
    codeInput.value = '';
    codeInput.focus();
    submitBtn.disabled = false;
  } catch (err) {
    feedbackText.textContent = 'Connection error. Please try again.';
    submitBtn.disabled = false;
  }
}

submitBtn.addEventListener('click', submitCode);
codeInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') submitCode();
});
"""