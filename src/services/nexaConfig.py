# This program generates the NexaBot Configuration file, used to define basic things about your NexaBot Installation
# It also parses the config file and provides an interface for accessing the config values.
# The config file is in YAML format, and is located at the root of the NexaBot installation as "nexaConfig.yaml". 
# If the file does not exist, it will be created with default values.
# Under the MIT License.

import sys
import logging
from pathlib import Path
from enum import IntEnum
from typing import Any, Dict, Optional, Set

import yaml

logger = logging.getLogger(__name__)

class PermissionLevel(IntEnum):
    EVERYONE = 0
    SUPERUSER = 1
    OPERATOR = 2
    HEAD_OPERATOR = 3

    @classmethod
    def from_str(cls, value: str, *, context: str = "") -> "PermissionLevel":
        try:
            return cls[_to_enum_name(value)]
        except KeyError:
            valid = ", ".join(m.name.lower() for m in cls)
            raise ValueError(
                f"Invalid permissionLevel '{value}'{f' for {context}' if context else ''}. "
                f"Must be one of: {valid}"
            )


def _to_enum_name(value: str) -> str:
    # "headOperator" / "head_operator" / "HEAD_OPERATOR" -> "HEAD_OPERATOR"
    out = []
    for ch in value:
        if ch.isupper() and out and out[-1] != "_":
            out.append("_")
        out.append(ch.upper())
    return "".join(out).replace("__", "_")

class NexaConfig:
    DEFAULT_CONFIG: Dict[str, Any] = {
        "general": {
            "instancesFolder": "instances",
            "primaryInstance": None,
            "configVersion": 1,
        },
        "discord": {
            "enable": True,
            "lockToAuthorizedGuild": False,
            "authorizedGuilds": [],
            "statusChannelID": 0,
            "healthIssuesChannelID": 0,
            "updateInterval": 30,
            "enableSuperUsers": False,
            "superUsers": [],
        },
        "security": {
            "enableServerOperators": False,
            "serverOperators": [],
            "headOperator": 0,
            "shadyAuthAttemptThreshold": 10,
            "sftpConnectionLengthInMins": 15,
            "allowNexaDesktop": False,
        },
        "networking": {
            "usePlayIt": True,
        },
        "logging": {
            "enableFileLogging": True,
            "logFolder": "logs",
            "level": "INFO",
            "maxFileSizeMB": 5,
            "backupCount": 7,
            "components": {
                "rcon": "DEBUG",
                "discord": "DEBUG",
                "vm": "INFO",
                "config": "WARNING",
            },
        },
        "automaticModpackBootstrapper": {
            "strictModVerification": True,
        },
        "serverHealthManagement":{
            "keepNexaAlive": True,
            "keepAliveIntervalInSecs": 60,
            "keepPlayItAlive": True,
            "updateCheckIntervalInMins": 15,
        }
    }


    EXPECTED_TYPES = {
        "general": {
            "instancesFolder": str,
            "primaryInstance": (str, type(None)),
            "configVersion": int,
        },
        "discord": {
            "enable": bool,
            "lockToAuthorizedGuild": bool,
            "authorizedGuilds": list,
            "statusChannelID": int,
            "healthIssuesChannelID": int,
            "updateInterval": int,
            "enableSuperUsers": bool,
            "superUsers": list,
        },
        "security": {
            "enableServerOperators": bool,
            "serverOperators": list,
            "headOperator": int,
            "shadyAuthAttemptThreshold": int,
            "sftpConnectionLengthInMins": int,
            "allowNexaDesktop": bool,
        },
        "networking": {
            "usePlayIt": bool,
        },
        "logging": {
            "enableFileLogging": bool,
            "logFolder": str,
            "level": str,
            "maxFileSizeMB": int,
            "backupCount": int,
            "components": dict,
        },
        "automaticModpackBootstrapper": {
            "strictModVerification": bool,
        },
        "serverHealthManagement": {
            "keepNexaAlive": bool,
            "keepAliveIntervalInSecs": int,
            "keepPlayItAlive": bool,
            "updateCheckIntervalInMins": int,
        },
    }

    VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    def __init__(self, intendedPath: str, createifMissing: bool = True):
        self.configPath = Path(intendedPath)

        if not self.configPath.exists():
            if createifMissing:
                self._createDefaultConfig()
            else:
                raise FileNotFoundError(f"Config file not found at {self.configPath} and createifMissing is False.")
            
        self._config: Dict[str, Any] = {}
        self._load()

    # Private Methods
    def _createDefaultConfig(self):
        self.configPath.parent.mkdir(parents=True, exist_ok=True)
        with open(self.configPath, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.DEFAULT_CONFIG, f, sort_keys=False)

    def _load(self):
        with open(self.configPath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        changed = self._mergeDefaults(data, self.DEFAULT_CONFIG)
        self._validate(data)

        self._config = data

        if changed:
            self.save()

    def _mergeDefaults(self, data: Dict[str, Any], defaults: Dict[str, Any]) -> bool:
        changed = False

        for key, value in defaults.items():
            if key not in data:
                data[key] = value
                changed = True
            elif isinstance(value, dict):
                if not isinstance(data[key], dict):
                    raise TypeError(f"Section '{key}' must be a dictionary.")
                # Special case: logging.components is user-defined, skip recursive merge/rejection
                if key == "components":
                    continue
                if self._mergeDefaults(data[key], value):
                    changed = True

        # Remove unknown keys
        for key in list(data.keys()):
            if key not in defaults:
                # raise KeyError(f"Unknown configuration key: {key}")
                del data[key]
                changed = True

        return changed

    def _validate(self, data: Dict[str, Any]):
        for section, keys in self.EXPECTED_TYPES.items():
            if section not in data:
                raise KeyError(f"Missing configuration section: {section}")

            for key, expected_type in keys.items():
                value = data[section].get(key)
                if not isinstance(value, expected_type):
                    raise TypeError(
                        f"Invalid type for '{section}.{key}'. "
                        f"Expected {expected_type}, got {type(value)}"
                    )

        # Validate global log level
        level = data["logging"]["level"].upper()
        if level not in self.VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log level '{level}'. Must be one of {self.VALID_LOG_LEVELS}."
            )

        # Validate per-component log levels
        for component, comp_level in data["logging"]["components"].items():
            if not isinstance(component, str):
                raise TypeError(f"Component name '{component}' must be a string.")
            if not isinstance(comp_level, str):
                raise TypeError(f"Log level for component '{component}' must be a string.")
            if comp_level.upper() not in self.VALID_LOG_LEVELS:
                raise ValueError(
                    f"Invalid log level '{comp_level}' for component '{component}'. "
                    f"Must be one of {self.VALID_LOG_LEVELS}."
                )

        # Existing validation
        guilds = data["discord"]["authorizedGuilds"]
        if not all(isinstance(g, int) for g in guilds):
            raise TypeError("All entries in 'discord.authorizedGuilds' must be integers.")

    # Public Methods
    def save(self):
        with open(self.configPath, "w", encoding = "utf-8") as f:
            yaml.safe_dump(self._config, f, sort_keys=False)

    def reload(self):
        self._load()

    def get(self, path: str, default=None):
        keys = path.split(".")
        value = self._config

        for key in keys:
            if key not in value:
                return default
            value = value[key]
        return value
    
    def set(self, path: str, value: Any):
        keys = path.split(".")
        target = self._config

        for key in keys[:-1]:
            if key not in target:
                raise KeyError(f"Invalid Path: {path}")
            target = target[key]

        target[keys[-1]] = value

    def dumpData(self) -> Dict[str, Any]:
        return self._config

    def __getattr__(self, item):
        if item in self._config:
            return _SectionProxy(self._config[item])
        raise AttributeError(item)

    def __repr__(self):
        return f"<NexaConfig path='{self.configPath}'>"

class NexaInstanceRegistry:

    DEFAULT_INSTANCE_TEMPLATE: Dict[str, Any] = {
        "displayName": "",
        "version": "",
        "loaderType": "",
        "icon_url": "",
        "folder": "",
        "enableAutomations": False,
    }

    EXPECTED_TYPES = {
        "displayName": str,
        "version": str,
        "loaderType": str,
        "icon_url": str,
        "folder": str,
        "enableAutomations": bool,
    }

    def __init__(self, intendedPath: str, createIfMissing: bool = True):
        self.registryPath = Path(intendedPath)

        if not self.registryPath.exists():
            if createIfMissing:
                self._createDefaultRegistry()
            else:
                raise FileNotFoundError(
                    f"Instance registry not found at {self.registryPath}"
                )

        self._data: Dict[str, Any] = {}
        self._load()

    # Private Methods
    def _createDefaultRegistry(self):
        self.registryPath.parent.mkdir(parents=True, exist_ok=True)
        with open(self.registryPath, "w", encoding="utf-8") as f:
            yaml.safe_dump({"instances": {}}, f, sort_keys=False)

    def _load(self):
        with open(self.registryPath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if "instances" not in data:
            raise KeyError("Missing 'instances' root key in registry file.")

        if not isinstance(data["instances"], dict):
            raise TypeError("'instances' must be a dictionary.")

        self._validate_instances(data["instances"])
        self._data = data

    def _validate_instances(self, instances: Dict[str, Any]):
        for instance_name, config in instances.items():

            if not isinstance(instance_name, str):
                raise TypeError("Instance names must be strings.")

            if not isinstance(config, dict):
                raise TypeError(
                    f"Instance '{instance_name}' must be a dictionary."
                )

            # Ensure no unknown keys
            for key in config:
                if key not in self.EXPECTED_TYPES:
                    raise KeyError(
                        f"Unknown key in instance '{instance_name}': {key}"
                    )

            # Merge missing defaults
            for key, default_value in self.DEFAULT_INSTANCE_TEMPLATE.items():
                if key not in config:
                    config[key] = default_value

            # Type validation
            for key, expected_type in self.EXPECTED_TYPES.items():
                value = config.get(key)
                if not isinstance(value, expected_type):
                    raise TypeError(
                        f"Invalid type for '{instance_name}.{key}'. "
                        f"Expected {expected_type}, got {type(value)}"
                    )

    # Public Methods
    def save(self):
        with open(self.registryPath, "w", encoding="utf-8") as f:
            yaml.safe_dump(self._data, f, sort_keys=False)

    def reload(self):
        self._load()

    def get_instance(self, name: str) -> Dict[str, Any]:
        return self._data["instances"].get(name)

    def list_instances(self):
        return list(self._data["instances"].keys())

    def add_instance(self, name: str, config: Dict[str, Any]):
        if name in self._data["instances"]:
            raise KeyError(f"Instance '{name}' already exists.")

        self._data["instances"][name] = config
        self._validate_instances({name: config})
        self.save()

    def remove_instance(self, name: str):
        if name not in self._data["instances"]:
            raise KeyError(f"Instance '{name}' not found.")

        del self._data["instances"][name]
        self.save()

    def dumpData(self) -> Dict[str, Any]:
        return self._data

    def __repr__(self):
        return f"<NexaInstanceRegistry path='{self.registryPath}'>"

class NexaInstanceConfig:
    """
    Per-instance configuration loaded from nexaServerSettings.yaml inside each instance folder.
    Handles functionality settings (startCmd, join_to_wake, watchdog) and security settings
    (protected_commands). Creates a default config if the file does not exist.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "configVersion": 1,
        "functionality": {
            "startCmd": "java -Xmx4G -Xms4G -jar server.jar nogui",
            "join_to_wake": False,
            "watchdog": {
                "enabled": True,
                "interval_seconds": 60,
                "restart_limit": 3,
            },
            "autosave": {
                "enabled": True,
                "interval_days": 3,
            },
            "auto_shutdown": {
                "enabled": False,
                "idle_minutes": 5,
            },
        },
        "security": {
            "protected_commands": {
                "enabled": True,
                "commands": [
                    "whitelist",
                    "kick",
                    "ban",
                    "op",
                    "deop",
                    "stop",
                    "execute",
                ],
            },
        },
    }

    EXPECTED_TYPES = {
        "configVersion": int,
        "functionality": {
            "startCmd": str,
            "join_to_wake": bool,
            "watchdog": {
                "enabled": bool,
                "interval_seconds": int,
                "restart_limit": int,
            },
            "autosave": {
                "enabled": bool,
                "interval_days": int,
            },
            "auto_shutdown": {
                "enabled": bool,
                "idle_minutes": int,
            },
        },
        "security": {
            "protected_commands": {
                "enabled": bool,
                "commands": list,
            },
        },
    }

    def __init__(self, instanceFolder: Path, createIfMissing: bool = True):
        self.configPath = instanceFolder / "nexaServerSettings.yaml"

        if not self.configPath.exists():
            if createIfMissing:
                self._createDefaultConfig()
            else:
                raise FileNotFoundError(
                    f"Instance config not found at {self.configPath} and createIfMissing is False."
                )

        self._config: Dict[str, Any] = {}
        self._load()

    # Private Methods
    def _createDefaultConfig(self):
        self.configPath.parent.mkdir(parents=True, exist_ok=True)
        with open(self.configPath, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.DEFAULT_CONFIG, f, sort_keys=False)

    def _load(self):
        with open(self.configPath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        changed = self._mergeDefaults(data, self.DEFAULT_CONFIG)
        self._validate(data, self.EXPECTED_TYPES)

        self._config = data

        if changed:
            self.save()

    def _mergeDefaults(self, data: Dict[str, Any], defaults: Dict[str, Any]) -> bool:
        changed = False

        for key, value in defaults.items():
            if key not in data:
                data[key] = value
                changed = True
            elif isinstance(value, dict):
                if not isinstance(data[key], dict):
                    raise TypeError(f"Section '{key}' must be a dictionary.")
                if self._mergeDefaults(data[key], value):
                    changed = True

        # Remove unknown keys
        for key in list(data.keys()):
            if key not in defaults:
                # raise KeyError(f"Unknown configuration key in instance config: {key}")
                del data[key]
                changed = True

        return changed

    def _validate(self, data: Dict[str, Any], expected: Dict[str, Any], path: str = ""):
        for key, expected_type in expected.items():
            full_path = f"{path}.{key}" if path else key

            if key not in data:
                raise KeyError(f"Missing key in instance config: {full_path}")

            if isinstance(expected_type, dict):
                if not isinstance(data[key], dict):
                    raise TypeError(f"Expected dictionary at '{full_path}', got {type(data[key])}")
                self._validate(data[key], expected_type, full_path)
            else:
                if not isinstance(data[key], expected_type):
                    raise TypeError(
                        f"Invalid type for '{full_path}'. "
                        f"Expected {expected_type}, got {type(data[key])}"
                    )

        # Validate protected_commands list contains only strings
        if "security" in data:
            cmds = data["security"].get("protected_commands", {}).get("commands", [])
            if not all(isinstance(c, str) for c in cmds):
                raise TypeError("All entries in 'security.protected_commands.commands' must be strings.")

    # Public Methods
    def save(self):
        with open(self.configPath, "w", encoding="utf-8") as f:
            yaml.safe_dump(self._config, f, sort_keys=False)

    def reload(self):
        self._load()

    def get(self, path: str, default=None):
        """
        Getter method using dot notation.
        e.g. get("functionality.watchdog.restart_limit")
        """
        keys = path.split(".")
        value = self._config

        for key in keys:
            if not isinstance(value, dict) or key not in value:
                return default
            value = value[key]
        return value

    def dumpData(self) -> Dict[str, Any]:
        return self._config

    def __repr__(self):
        return f"<NexaInstanceConfig path='{self.configPath}'>"

class NexaCmdConfig:
    """
    Loads and validates NexaBotCmdCfg.yaml, the per-command configuration
    for Nexa's Discord command surface (enable/disable, permission tiers,
    authentication requirements, and command-specific options).

    Follows the same load/merge-defaults/validate/save pattern as NexaConfig.
    """

    # Commands that are load-bearing for bot operation and cannot be disabled.
    CORE_COMMANDS: Set[str] = {
        "start",
        "start_specific",
        "stop",
        "stop_specific",
    }

    # Per-command restrictions on which permission levels are valid.
    # Commands not listed here allow any PermissionLevel.
    ALLOWED_PERMISSION_LEVELS: Dict[str, Set[PermissionLevel]] = {
        "fsaccess": {PermissionLevel.OPERATOR, PermissionLevel.HEAD_OPERATOR},
        "keyman": {PermissionLevel.HEAD_OPERATOR},
    }

    DEFAULT_CONFIG: Dict[str, Any] = {
        "commands": {
            "status": {
                "enabled": True,
                "permissionLevel": "everyone",
            },
            "start": {
                "permissionLevel": "everyone",
            },
            "start_specific": {
                "permissionLevel": "everyone",
            },
            "stop": {
                "permissionLevel": "superuser",
            },
            "stop_specific": {
                "permissionLevel": "superuser",
            },
            "execute": {
                "enabled": True,
                "permissionLevel": "operator",
                "requireAuthentication": True,
            },
            "lock_instance": {
                "enabled": True,
                "permissionLevel": "operator",
                "requireAuthentication": False,
            },
            "unlock_instance": {
                "enabled": True,
                "permissionLevel": "operator",
                "requireAuthentication": False,
            },
            "force_stop": {
                "enabled": True,
                "permissionLevel": "operator",
            },
            "install_mcpk": {
                "enabled": True,
                "permissionLevel": "operator",
                "requireAuthentication": True,
                "shutdownWaitPeriodInMins": 15,
            },
            "keyman": {
                "enabled": True,
                "permissionLevel": "headOperator",
                "issue": {
                    "requireAuthentication": True,
                },
                "modify": {
                    "requireAuthentication": True,
                },
                "revoke": {
                    "requireAuthentication": True,
                },
                "rotate": {
                    "requireAuthentication": True,
                },
                "list": {
                    "requireAuthentication": True,
                },
            },
            "fsaccess": {
                "enabled": True,
                "permissionLevel": "operator",
                "requireAuthentication": True,
                "askHeadOperatorForApproval": True,
            },
            "check_updates": {
                "enabled": True,
                "permissionLevel": "superuser",
            },
        }
    }

    EXPECTED_TYPES: Dict[str, Any] = {
        "status": {
            "enabled": bool,
            "permissionLevel": str,
        },
        "start": {
            "permissionLevel": str,
        },
        "start_specific": {
            "permissionLevel": str,
        },
        "stop": {
            "permissionLevel": str,
        },
        "stop_specific": {
            "permissionLevel": str,
        },
        "execute": {
            "enabled": bool,
            "permissionLevel": str,
            "requireAuthentication": bool,
        },
        "lock_instance": {
            "enabled": bool,
            "permissionLevel": str,
            "requireAuthentication": bool,
        },
        "unlock_instance": {
            "enabled": bool,
            "permissionLevel": str,
            "requireAuthentication": bool,
        },
        "force_stop": {
            "enabled": bool,
            "permissionLevel": str,
        },
        "install_mcpk": {
            "enabled": bool,
            "permissionLevel": str,
            "requireAuthentication": bool,
            "shutdownWaitPeriodInMins": int,
        },
        "keyman": {
            "enabled": bool,
            "permissionLevel": str,
            "issue": {
                "requireAuthentication": bool,
            },
            "modify": {
                "requireAuthentication": bool,
            },
            "revoke": {
                "requireAuthentication": bool,
            },
            "rotate": {
                "requireAuthentication": bool,
            },
            "list": {
                "requireAuthentication": bool,
            },
        },
        "fsaccess": {
            "enabled": bool,
            "permissionLevel": str,
            "requireAuthentication": bool,
            "askHeadOperatorForApproval": bool,
        },
        "check_updates": {
            "enabled": bool,
            "permissionLevel": str,
        },
    }

    def __init__(self, intendedPath: str, createIfMissing: bool = True):
        self.configPath = Path(intendedPath)

        if not self.configPath.exists():
            if createIfMissing:
                self._createDefaultConfig()
            else:
                raise FileNotFoundError(
                    f"Config file not found at {self.configPath} and createIfMissing is False."
                )

        self._config: Dict[str, Any] = {}
        self._load()

    def _createDefaultConfig(self):
        self.configPath.parent.mkdir(parents=True, exist_ok=True)
        with open(self.configPath, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.DEFAULT_CONFIG, f, sort_keys=False)

    def _load(self):
        with open(self.configPath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self._validate(data)

        changed = self._mergeDefaults(data, self.DEFAULT_CONFIG)

        self._cachePermissionLevels(data.get("commands", {}))

        self._config = data

        if changed:
            self.save()

    def _cachePermissionLevels(self, commands: Dict[str, Any]):
        for name, entry in commands.items():
            if isinstance(entry, dict) and "permissionLevel" in entry:
                entry["_permissionLevelEnum"] = PermissionLevel.from_str(entry["permissionLevel"])

    def _mergeDefaults(self, data: Dict[str, Any], defaults: Dict[str, Any]) -> bool:
        changed = False

        for key, value in defaults.items():
            if key not in data:
                data[key] = value
                changed = True
            elif isinstance(value, dict):
                if not isinstance(data[key], dict):
                    raise TypeError(f"Section '{key}' must be a dictionary.")
                if self._mergeDefaults(data[key], value):
                    changed = True

        for key in list(data.keys()):
            if key not in defaults:
                del data[key]
                changed = True

        return changed

    def _validate(self, data: Dict[str, Any]):
        if "commands" not in data or not isinstance(data["commands"], dict):
            self._fatal("Missing or invalid top-level 'commands' section.")

        commands = data["commands"]

        for name, entry in commands.items():
            if not isinstance(entry, dict):
                self._fatal(f"Command entry '{name}' must be a mapping.")

            self._validateCoreCommandRule(name, entry)
            self._validatePermissionLevel(name, entry)

            expected = self.EXPECTED_TYPES.get(name)
            if expected is not None:
                self._validateTypes(entry, expected, path=name)

    def _validateTypes(self, data: Dict[str, Any], expected: Dict[str, Any], path: str):
        for key, expectedType in expected.items():
            fullPath = f"{path}.{key}"

            if key not in data:
                continue

            if isinstance(expectedType, dict):
                if not isinstance(data[key], dict):
                    self._fatal(f"'{fullPath}' must be a mapping.")
                self._validateTypes(data[key], expectedType, fullPath)
            else:
                if not isinstance(data[key], expectedType):
                    self._fatal(
                        f"Invalid type for '{fullPath}'. "
                        f"Expected {expectedType}, got {type(data[key]).__name__}."
                    )

    def _validateCoreCommandRule(self, name: str, entry: Dict[str, Any]):
        if name in self.CORE_COMMANDS and "enabled" in entry:
            self._fatal(
                f"'{name}' is a core command and cannot define 'enabled' "
                f"(core commands are always enabled; Nexa will not function "
                f"correctly if disabled). See the handbook/wiki for details."
            )

    def _validatePermissionLevel(self, name: str, entry: Dict[str, Any]):
        if "permissionLevel" not in entry:
            return

        raw = entry["permissionLevel"]
        if not isinstance(raw, str):
            self._fatal(f"'{name}.permissionLevel' must be a string.")

        try:
            level = PermissionLevel.from_str(raw, context=f"command '{name}'")
        except ValueError as e:
            self._fatal(str(e))
            return  # unreachable; _fatal calls sys.exit(1)

        allowed = self.ALLOWED_PERMISSION_LEVELS.get(name)
        if allowed is not None and level not in allowed:
            allowedNames = ", ".join(sorted(l.name.lower() for l in allowed))
            self._fatal(
                f"permissionLevel '{raw}' is not allowed for '{name}'. "
                f"Allowed levels: {allowedNames}."
            )

    def _fatal(self, message: str):
        logger.error(f"[NexaCmdConfig] Invalid configuration: {message}")
        sys.exit(1)

    # Public Methods
    def save(self):
        # Strip derived/internal keys before persisting.
        cleaned = self._stripInternal(self._config)
        with open(self.configPath, "w", encoding="utf-8") as f:
            yaml.safe_dump(cleaned, f, sort_keys=False)

    def _stripInternal(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k: self._stripInternal(v)
                for k, v in data.items()
                if not k.startswith("_")
            }
        return data

    def reload(self):
        self._load()

    def isEnabled(self, command: str) -> bool:
        entry = self._config.get("commands", {}).get(command, {})
        if command in self.CORE_COMMANDS:
            return True
        return bool(entry.get("enabled", False))

    def getPermissionLevel(self, command: str) -> Optional[PermissionLevel]:
        entry = self._config.get("commands", {}).get(command, {})
        return entry.get("_permissionLevelEnum")

    def requiresAuthentication(self, command: str, subaction: Optional[str] = None) -> bool:
        commands = self._config.get("commands", {})
        entry = commands.get(command, {})
        if subaction is not None:
            entry = entry.get(subaction, {})
        return bool(entry.get("requireAuthentication", False))

    def get(self, path: str, default=None):
        keys = path.split(".")
        value = self._config

        for key in keys:
            if not isinstance(value, dict) or key not in value:
                return default
            value = value[key]
        return value

    def dumpData(self) -> Dict[str, Any]:
        return self._stripInternal(self._config)

    def __repr__(self):
        return f"<NexaCmdConfig path='{self.configPath}'>"

class _SectionProxy:
    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def __getattr__(self, item):
        if item in self._data:
            return self._data[item]
        raise AttributeError(item)

    def __repr__(self):
        return repr(self._data)