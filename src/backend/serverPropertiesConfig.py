# Class-based rewrite of the original Minecraft server.properties config manager.
# Under the MIT License.

import secrets
import string
from pathlib import Path
from typing import Dict, Optional, Union

ConfigValue = Union[str, bool]


class ServerPropertiesConfig:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"Config file not found at {self.path}")

        # _lines preserves the file verbatim, line by line, in original order.
        # _index maps key -> line number in _lines, for O(1) lookup/rewrite.
        # Comment lines and blank lines are never in _index.
        self._lines: list[str] = []
        self._index: Dict[str, int] = {}
        self._load()

    # --- Private methods ----------------------------------------------

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            self._lines = f.read().splitlines()

        self._index.clear()
        for lineNumber, rawLine in enumerate(self._lines):
            line = rawLine.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue  # malformed, treat as opaque like a comment
            key = line.split("=", 1)[0].strip()
            self._index[key] = lineNumber

    def _coerce(self, rawValue: str) -> ConfigValue:
        lowered = rawValue.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return rawValue

    def _serialize(self, value: ConfigValue) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    # --- Public methods -------------------------------------------------

    def get(self, key: str, default: Optional[ConfigValue] = None) -> Optional[ConfigValue]:
        lineNumber = self._index.get(key)
        if lineNumber is None:
            return default
        rawValue = self._lines[lineNumber].split("=", 1)[1]
        return self._coerce(rawValue)

    def set(self, key: str, value: ConfigValue, save: bool = True):
        """
        Sets a single key, rewriting its line in place if it already exists,
        or appending a new key=value line at the end of the file if it
        doesn't. Writes to disk immediately unless save=False (useful when
        the caller is about to make several set() calls and wants to batch
        them -- though setMany() is the preferred way to do that atomically).
        """
        serialized = self._serialize(value)
        lineNumber = self._index.get(key)

        if lineNumber is not None:
            self._lines[lineNumber] = f"{key}={serialized}"
        else:
            self._lines.append(f"{key}={serialized}")
            self._index[key] = len(self._lines) - 1

        if save:
            self.save()

    def setMany(self, values: Dict[str, ConfigValue]):
        """
        Sets multiple keys and writes the file exactly once. Use this
        instead of multiple set() calls when several keys need to change
        together (e.g. enabling RCON also requires setting its password) --
        one disk write instead of several, and no window where the file is
        left in a half-updated state between them.
        """
        for key, value in values.items():
            self.set(key, value, save=False)
        self.save()

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(self._lines) + "\n")

    def reload(self):
        self._load()

    def dumpData(self) -> Dict[str, ConfigValue]:
        return {
            key: self._coerce(self._lines[lineNumber].split("=", 1)[1])
            for key, lineNumber in self._index.items()
        }

    def __repr__(self):
        return f"<ServerPropertiesConfig path='{self.path}'>"


# --- RCON helper --------------------------------------------------------

def generateRconPassword(length: int = 32) -> str:
    """
    Generates a random alphanumeric password (no symbols) of the given
    length, using secrets rather than random since this produces a live
    credential written straight into server.properties.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensureRconEnabled(config: ServerPropertiesConfig) -> Optional[str]:
    """
    If RCON is disabled, enables it and sets a freshly generated 32-char
    alphanumeric password, writing both changes in a single save(). Returns
    the generated password if one was just set, or None if RCON was already
    enabled and nothing changed.

    NOTE: this always regenerates the password when RCON is off, even if
    rcon.password already has a leftover value from a previous session --
    matches "if RCON is disabled, set it as enabled and give it a random
    password" as the stated intent, rather than trying to guess whether an
    existing leftover password is still trustworthy.
    """
    if config.get("enable-rcon", False):
        return None

    password = generateRconPassword(32)
    config.setMany({
        "enable-rcon": True,
        "rcon.password": password,
    })
    return password