"""
nexaAuthenticationService.py

Handles Nexa's authentication key lifecycle for both the Head Operator's root credential
and codes issued to other Server Operators via /keyman:

    Head Operator root credential:
        - Bootstraps the Head Operator's setup key from a one-time consumable file (setupAuthKey.txt).
        - Hashes and stores the key (with a per-secret salt) inside the encrypted keys.nxdb database.
        - Deletes the plaintext file immediately after successful ingestion.
        - Detects and warns on stray/overwrite attempts of setupAuthKey.txt after a hash is already stored.
        - Hard-fails Nexa startup if no key is configured and none can be found.

    Operator-issued keys (/keyman):
        - Issues Nexa-generated, capability-scoped codes to Server Operators.
        - Codes are stored hash-first (hash is the DB key) so auth-time lookup is O(1) - resolving
          a candidate code straight to its capabilities without needing to know who presented it.
        - Modify/revoke/rotate operate by scanning for a matching discordUserID, since those are
          cold-path operations; only auth-time verification needs to be fast.
        - One active code per operator, enforced at issue-time.

This service does not handle TOTP or SFTP session lifecycle - those remain separate pieces
built on top of this foundation.
"""

import os
import secrets
import hmac
from pathlib import Path
from Crypto.Protocol.KDF import scrypt

from services.nexaConfig import NexaConfig


class HeadOperatorKeyMissingError(Exception):
    """Raised when no Head Operator key is configured and no setup file is present. Fatal - Nexa cannot start."""
    pass


class HeadOperatorKeyInvalidError(Exception):
    """Raised when setupAuthKey.txt exists but its contents fail validation (e.g. key too short)."""
    pass


class OperatorKeyAlreadyExistsError(Exception):
    """Raised when /keyman issue targets an operator who already holds an active key."""
    pass


class OperatorKeyNotFoundError(Exception):
    """Raised when /keyman modify/revoke/rotate targets an operator with no active key."""
    pass


class InvalidCapabilityError(Exception):
    """Raised when a capability string outside the known set is supplied."""
    pass


class NexaAuthenticationService:
    """
    Manages the Head Operator's root authentication key.

    Storage layout inside keys.nxdb:
        headOperatorKeyHash.hash -> str (hex-encoded scrypt hash)
        headOperatorKeyHash.salt -> str (hex-encoded random salt)

    Expected usage on Nexa startup:
        authService = NexaAuthenticationService(protectedDB=keysDB, configClass=config)
        await authService.bootstrap()
    """

    SETUP_FILE_NAME = "setupAuthKey.txt"
    DB_ENTRY_KEY = "headOperatorKeyHash"
    MIN_KEY_LENGTH = 16

    # scrypt cost parameters - conservative defaults, tune later if needed
    SCRYPT_N = 2 ** 14
    SCRYPT_R = 8
    SCRYPT_P = 1
    SCRYPT_DKLEN = 64
    SALT_BYTES = 16

    # --- Operator key (/keyman) settings ---
    OPERATOR_KEYS_ROOT = "additionalOperatorKeys"
    KNOWN_CAPABILITIES = {"modpackInstalls", "fsaccess", "lockAndUnlockInstances", "executeRCON"}  # extend as new capabilities are added

    # Operator codes use a FIXED salt (unlike the Head Operator's per-entry salt) so that
    # verifyOperatorKey() can hash the candidate once and do a direct dict-key lookup - true
    # O(1) auth, no scanning, no re-hashing per stored entry. This is safe specifically because
    # operator codes are Nexa-generated high-entropy random strings, not human-chosen secrets -
    # there's no dictionary/rainbow-table risk a per-entry salt would need to defend against here.
    # Mirrors protectedDB's own use of a fixed static salt for its KDF.
    OPERATOR_CODE_SALT = b"nexaOperatorKeys-fixed-salt-Qx7mP2vLk9"

    # Code generation: random, alphanumeric, ambiguous characters excluded, grouped for manual entry.
    # Excludes 0/O, 1/I/L to reduce transcription errors when typed by hand on arbitrary devices.
    CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
    CODE_GROUP_COUNT = 4
    CODE_GROUP_LENGTH = 4

    def __init__(self, protectedDB, configClass: NexaConfig, notifier=None, workingDirectory: str = None):
        """
        Args:
            protectedDB: An instance of the encrypted database class (exposes load/unload/
                         fetchEntry/setEntry/addEntry/deleteEntry/exists/prime).
            configClass: A NexaConfig instance. Stored as self.config and passed through to
                         NexaVerifService, which reads security.shadyAuthAttemptThreshold from
                         it. Required as a constructor argument (not read fresh from disk at
                         check-time) specifically to avoid a stale-read/TOCTOU-style race where
                         config could change mid-evaluation of a threshold decision - the
                         config this service uses is pinned for its whole lifetime.
            notifier: Optional object exposing methods to notify the Head Operator and/or
                      all Server Operators. If not provided, warnings are logged only.
                      Expected interface (stubbed for now):
                          notifier.dmHeadOperator(message: str) -> None
                          notifier.dmAllOperators(message: str) -> None
                      dmAllOperators is used by NexaVerifService's shady-activity
                      detection to reach every Server Operator plus the Head Operator,
                      not just the Head Operator alone.
            workingDirectory: Override for where setupAuthKey.txt is expected. Defaults to CWD,
                               matching Nexa's run context (wherever the binary/source is invoked from).
        """
        self.protectedDB = protectedDB
        self.config = configClass
        self.notifier = notifier
        self.workingDirectory = Path(workingDirectory) if workingDirectory else Path.cwd()
        self.setupFilePath = self.workingDirectory / self.SETUP_FILE_NAME

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def bootstrap(self) -> None:
        """
        Runs the full Head Operator key bootstrap sequence. Call once on Nexa startup,
        before any /keyman or filesystem-access-gated features are allowed to register.

        Async because the stray-file-warning path (_handleExistingHashState) may need
        to await a notifier DM to the Head Operator - the whole call chain from here
        down to notifier.dmHeadOperator() must be async and awaited throughout, or the
        DM silently never sends (an unawaited coroutine is just discarded, not an error).

        Raises:
            HeadOperatorKeyMissingError: no hash stored AND no setup file present. Fatal.
            HeadOperatorKeyInvalidError: setup file present but fails validation. Fatal.
        """
        self.protectedDB.load()
        try:
            hashAlreadyStored = self.protectedDB.exists(self.DB_ENTRY_KEY)

            if hashAlreadyStored:
                await self._handleExistingHashState()
                return

            # No hash stored yet - this is first-run bootstrap.
            if not self.setupFilePath.exists():
                raise HeadOperatorKeyMissingError(
                    f"No Head Operator key configured and '{self.SETUP_FILE_NAME}' not found "
                    f"in '{self.workingDirectory}'. Nexa cannot start without a Head Operator key. "
                    f"Create '{self.SETUP_FILE_NAME}' containing 'key=<your key, {self.MIN_KEY_LENGTH}+ chars>' "
                    f"and restart."
                )

            self._ingestSetupFile()
        finally:
            self.protectedDB.unload()

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    async def _handleExistingHashState(self) -> None:
        """
        A hash is already stored. If setupAuthKey.txt is also present, this is either a
        stray leftover from a prior run or an attempted overwrite - either way, delete it
        and warn the Head Operator. Never re-ingest silently.
        """
        if not self.setupFilePath.exists():
            return  # Normal steady state - nothing to do.

        self._deleteSetupFile()
        warningMessage = (
            f"'{self.SETUP_FILE_NAME}' was found on disk even though a Head Operator key is "
            f"already configured. The file has been deleted without being read. If you intended "
            f"to rotate your key, this is not the correct path - the existing key must be revoked "
            f"first through the appropriate rotation process."
        )
        await self._warnHeadOperator(warningMessage)

    def _ingestSetupFile(self) -> None:
        """
        Reads, validates, hashes, and stores the setup key. Deletes the plaintext file
        immediately after the hash is committed to protectedDB.
        """
        rawContents = self.setupFilePath.read_text(encoding="utf-8").strip()

        key = self._parseKeyValue(rawContents)

        if len(key) < self.MIN_KEY_LENGTH:
            # Deliberately do NOT delete the file here - leave it in place so the
            # Head Operator can fix the content in place and restart, rather than
            # having to regenerate the whole file from scratch.
            raise HeadOperatorKeyInvalidError(
                f"Key in '{self.SETUP_FILE_NAME}' is too short "
                f"({len(key)} chars, minimum is {self.MIN_KEY_LENGTH}). "
                f"File left in place - fix the key value and restart."
            )

        hashHex, saltHex = self._hashKey(key)

        # Commit to DB first, then delete the file - if the process dies between
        # these two steps, next startup's _handleExistingHashState() branch will
        # detect the stray file and clean it up safely (see docs/design notes).
        self.protectedDB.addEntry(self.DB_ENTRY_KEY, {
            "hash": hashHex,
            "salt": saltHex,
        })

        self._deleteSetupFile()

        print(f"[NexaAuthenticationService] Head Operator key successfully ingested and hashed. "
              f"'{self.SETUP_FILE_NAME}' has been deleted.")

    def _parseKeyValue(self, rawContents: str) -> str:
        """
        Parses the 'key=<value>' line format. Raises HeadOperatorKeyInvalidError on
        malformed content rather than silently returning something wrong.
        """
        for line in rawContents.splitlines():
            line = line.strip()
            if line.startswith("key="):
                return line[len("key="):].strip()

        raise HeadOperatorKeyInvalidError(
            f"'{self.SETUP_FILE_NAME}' does not contain a valid 'key=<value>' line. "
            f"File left in place - fix the format and restart."
        )

    def _hashKey(self, key: str) -> tuple:
        """
        Hashes the given key with a freshly generated random salt using scrypt.
        Returns (hashHex, saltHex).
        """
        salt = secrets.token_bytes(self.SALT_BYTES)
        derived = scrypt(
            key.encode("utf-8"),
            salt,
            key_len=self.SCRYPT_DKLEN,
            N=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
        )
        return derived.hex(), salt.hex()

    def _deleteSetupFile(self) -> None:
        try:
            self.setupFilePath.unlink()
        except FileNotFoundError:
            pass  # Already gone - not an error state.

    async def _warnHeadOperator(self, message: str) -> None:
        print(f"[NexaAuthenticationService][WARNING] {message}")
        if self.notifier is not None:
            await self.notifier.dmHeadOperator(message)
        else:
            print("[NexaAuthenticationService] No notifier configured - warning was only logged, "
                  "not delivered to the Head Operator via DM.")

    # ------------------------------------------------------------------
    # Verification (used later by /keyman and /fsaccess auth steps)
    # ------------------------------------------------------------------

    def verifyKey(self, candidateKey: str) -> bool:
        """
        Verifies a candidate key against the stored Head Operator hash.
        Loads/unloads protectedDB around the check to minimize memory residency.

        Returns:
            bool: True if candidateKey matches the stored hash, False otherwise.
        """
        self.protectedDB.load()
        try:
            if not self.protectedDB.exists(self.DB_ENTRY_KEY):
                return False

            stored = self.protectedDB.fetchEntry(self.DB_ENTRY_KEY)
            storedHashHex = stored.get("hash")
            saltHex = stored.get("salt")

            if not storedHashHex or not saltHex:
                return False

            salt = bytes.fromhex(saltHex)
            derived = scrypt(
                candidateKey.encode("utf-8"),
                salt,
                key_len=self.SCRYPT_DKLEN,
                N=self.SCRYPT_N,
                r=self.SCRYPT_R,
                p=self.SCRYPT_P,
            )

            return hmac.compare_digest(derived.hex(), storedHashHex)
        finally:
            self.protectedDB.unload()

    @property
    def isConfigured(self) -> bool:
        """
        Convenience check for other services/cogs to gate security-sensitive features on.
        Loads/unloads protectedDB around the check.
        """
        self.protectedDB.load()
        try:
            return self.protectedDB.exists(self.DB_ENTRY_KEY)
        finally:
            self.protectedDB.unload()

    # ------------------------------------------------------------------
    # Operator key management (/keyman)
    # ------------------------------------------------------------------

    def _generateCode(self) -> str:
        """
        Generates a random, grouped, manual-entry-friendly code from CODE_ALPHABET.
        e.g. 'X8KP-9QRM-4TVZ-2WHD'
        """
        groups = []
        for _ in range(self.CODE_GROUP_COUNT):
            group = "".join(secrets.choice(self.CODE_ALPHABET) for _ in range(self.CODE_GROUP_LENGTH))
            groups.append(group)
        return "-".join(groups)

    def _hashOperatorCode(self, code: str) -> str:
        """
        Hashes an operator code using the fixed OPERATOR_CODE_SALT. This is what enables
        O(1) auth-time lookup: hash the candidate once, use the result directly as the
        dict key, no scanning or salt lookup needed first.

        Dashes are stripped and casing is normalized before hashing, so the displayed
        grouped format ('X8KP-9QRM-4TVZ-2WHD') and a plain typed-out version
        ('X8KP9QRM4TVZ2WHD') hash identically. This is only applied to operator codes -
        the Head Operator's own key is chosen by them and hashed as-is, unmodified.
        """
        normalized = code.replace("-", "").upper()
        derived = scrypt(
            normalized.encode("utf-8"),
            self.OPERATOR_CODE_SALT,
            key_len=self.SCRYPT_DKLEN,
            N=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
        )
        return derived.hex()

    def _validateCapabilities(self, capabilities) -> list:
        """
        Validates a list/set of capability strings against KNOWN_CAPABILITIES.
        Raises InvalidCapabilityError on any unknown value - never silently drops one.
        """
        capabilities = list(dict.fromkeys(capabilities))  # de-dupe, preserve order
        unknown = [c for c in capabilities if c not in self.KNOWN_CAPABILITIES]
        if unknown:
            raise InvalidCapabilityError(
                f"Unknown capability/capabilities: {', '.join(unknown)}. "
                f"Known capabilities: {', '.join(sorted(self.KNOWN_CAPABILITIES))}."
            )
        return capabilities

    def _findOperatorEntry(self, discordUserID: int):
        """
        Scans additionalOperatorKeys for an entry matching discordUserID.
        Cold-path lookup only - auth-time verification never uses this.

        Returns:
            (hashKey, entryDict) if found, else (None, None).
        Requires protectedDB to already be loaded by the caller.
        """
        allEntries = self.protectedDB.fetchEntry(self.OPERATOR_KEYS_ROOT) or {}
        for hashKey, entry in allEntries.items():
            if entry.get("discordUserID") == discordUserID:
                return hashKey, entry
        return None, None

    def issueOperatorKey(self, discordUserID: int, capabilities: list) -> str:
        """
        Issues a new operator code with the given capabilities. Fails if the operator
        already holds an active code - one active code per operator, enforced here.

        Returns:
            str: The plaintext code. Shown to the caller exactly once - only its hash
                 and salt are persisted. The caller (cog) is responsible for delivering
                 this to the operator (e.g. via DM) and never logging it.
        Raises:
            OperatorKeyAlreadyExistsError: operator already has an active code.
            InvalidCapabilityError: an unknown capability was supplied.
        """
        capabilities = self._validateCapabilities(capabilities)

        self.protectedDB.load()
        try:
            existingHashKey, _ = self._findOperatorEntry(discordUserID)
            if existingHashKey is not None:
                raise OperatorKeyAlreadyExistsError(
                    f"Discord user {discordUserID} already has an active operator key. "
                    f"Revoke it first, or use /keyman rotate."
                )

            code = self._generateCode()
            hashHex = self._hashOperatorCode(code)

            self.protectedDB.addEntry(f"{self.OPERATOR_KEYS_ROOT}.{hashHex}", {
                "discordUserID": discordUserID,
                "capabilities": capabilities,
                "issuedOn": self._currentTimestamp(),
            })

            return code
        finally:
            self.protectedDB.unload()

    def modifyOperatorKey(self, discordUserID: int, capability: str, action: str) -> list:
        """
        Adds or removes a single capability from an operator's existing code, without
        touching the code/hash itself.

        Args:
            capability: A single capability string.
            action: "add" or "remove".

        Returns:
            list: The operator's updated capability list.
        Raises:
            OperatorKeyNotFoundError: operator has no active code.
            InvalidCapabilityError: capability is unknown, or action is not "add"/"remove".
        """
        if action not in ("add", "remove"):
            raise InvalidCapabilityError(f"Invalid action '{action}'. Must be 'add' or 'remove'.")

        validated = self._validateCapabilities([capability])
        capability = validated[0]

        self.protectedDB.load()
        try:
            hashKey, entry = self._findOperatorEntry(discordUserID)
            if hashKey is None:
                raise OperatorKeyNotFoundError(
                    f"Discord user {discordUserID} has no active operator key. Use /keyman issue first."
                )

            currentCapabilities = list(entry.get("capabilities", []))

            if action == "add":
                if capability not in currentCapabilities:
                    currentCapabilities.append(capability)
            else:  # remove
                if capability in currentCapabilities:
                    currentCapabilities.remove(capability)

            entry["capabilities"] = currentCapabilities
            self.protectedDB.setEntry(f"{self.OPERATOR_KEYS_ROOT}.{hashKey}", entry)

            return currentCapabilities
        finally:
            self.protectedDB.unload()

    def revokeOperatorKey(self, discordUserID: int) -> None:
        """
        Revokes (deletes) an operator's active code entirely.

        Raises:
            OperatorKeyNotFoundError: operator has no active code.
        """
        self.protectedDB.load()
        try:
            hashKey, _ = self._findOperatorEntry(discordUserID)
            if hashKey is None:
                raise OperatorKeyNotFoundError(
                    f"Discord user {discordUserID} has no active operator key to revoke."
                )

            self.protectedDB.deleteEntry(f"{self.OPERATOR_KEYS_ROOT}.{hashKey}")
        finally:
            self.protectedDB.unload()

    def rotateOperatorKey(self, discordUserID: int) -> str:
        """
        Revokes an operator's existing code and issues a new one, carrying over the
        same capabilities. Use when a code is suspected leaked or simply needs refreshing.

        Returns:
            str: The new plaintext code (shown once, same handling rules as issueOperatorKey).
        Raises:
            OperatorKeyNotFoundError: operator has no active code to rotate.
        """
        self.protectedDB.load()
        try:
            hashKey, entry = self._findOperatorEntry(discordUserID)
            if hashKey is None:
                raise OperatorKeyNotFoundError(
                    f"Discord user {discordUserID} has no active operator key to rotate."
                )

            capabilities = list(entry.get("capabilities", []))

            self.protectedDB.deleteEntry(f"{self.OPERATOR_KEYS_ROOT}.{hashKey}")

            code = self._generateCode()
            newHashHex = self._hashOperatorCode(code)

            self.protectedDB.addEntry(f"{self.OPERATOR_KEYS_ROOT}.{newHashHex}", {
                "discordUserID": discordUserID,
                "capabilities": capabilities,
                "issuedOn": self._currentTimestamp(),
            })

            return code
        finally:
            self.protectedDB.unload()

    def listOperatorKeys(self, discordUserID: int = None) -> list:
        """
        Lists active operator key grants. Never returns plaintext codes or hashes -
        only metadata safe for display (Discord user, capabilities, issue date).

        Args:
            discordUserID: If given, filters to just that operator. If None, returns all.

        Returns:
            list[dict]: Each dict has keys: discordUserID, capabilities, issuedOn.
        """
        self.protectedDB.load()
        try:
            allEntries = self.protectedDB.fetchEntry(self.OPERATOR_KEYS_ROOT) or {}
            results = []
            for entry in allEntries.values():
                if discordUserID is not None and entry.get("discordUserID") != discordUserID:
                    continue
                results.append({
                    "discordUserID": entry.get("discordUserID"),
                    "capabilities": list(entry.get("capabilities", [])),
                    "issuedOn": entry.get("issuedOn"),
                })
            return results
        finally:
            self.protectedDB.unload()

    def verifyOperatorKey(self, candidateCode: str):
        """
        Verifies a candidate operator code. True O(1) auth-time lookup: hash the candidate
        once against the fixed OPERATOR_CODE_SALT, then do a direct dict-key hit - no
        scanning, no per-entry salt lookup, no re-hashing per stored entry.

        Returns:
            dict or None: The matching entry (discordUserID, capabilities, issuedOn) if
                          the code is valid, else None.
        """
        candidateHashHex = self._hashOperatorCode(candidateCode)

        self.protectedDB.load()
        try:
            entryKey = f"{self.OPERATOR_KEYS_ROOT}.{candidateHashHex}"
            if not self.protectedDB.exists(entryKey):
                return None

            entry = self.protectedDB.fetchEntry(entryKey)
            return {
                "discordUserID": entry.get("discordUserID"),
                "capabilities": list(entry.get("capabilities", [])),
                "issuedOn": entry.get("issuedOn"),
            }
        finally:
            self.protectedDB.unload()

    @staticmethod
    def _currentTimestamp() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()