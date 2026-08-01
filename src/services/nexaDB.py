# nexaDB.py - Nexa Database Service
# Database service entitled nexaDB for NexaBot components. Like boltDB /w security features.
# Provides both unprotected and encrypted database classes for flexible data storage needs.
# Under the MIT License.

import os
from pathlib import Path
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from services import nexaLoggerFactory
import inspect

logger = nexaLoggerFactory.get_logger("databases")

class unprotectedDB:
    """
    This is an UNECRYPTED database class for simple data storage without encryption.

    As a result, there is no assumed threat model. It is simply a JSON file storage with basic read/write capabilities.

    If you are a developer contributing, please consider the correct use case and scope of this class before adding features.

    # Methods:
    - load(): Load the database from the file into memory (private variable).
    - unload(): Unload the database from memory (private variable).
    - prime(): Creates data inside database that gets the database minimally functional. Usually just a {}.
    - fetchEntry(key: str): Getter method that fetches the data at a specific directory inside the database.
    - setEntry(key: str, value): Setter method that sets the data at a specific directory inside the database.
    - deleteEntry(key: str): Deleter method that deletes the data at a specific directory inside the database.
    - addEntry(key: str, value): Adds a new entry at a specific directory inside the database.
    - exists(key: str): Existence checker method that checks if a specific directory inside the database exists.
    """
    def __init__(self, dbPath: Path, create_if_missing: bool = False):
        logger.info(f"Unprotected Database construction invoked by {inspect.currentframe().f_back.f_globals['__name__']}.{inspect.currentframe().f_back.f_code.co_name}() at line {inspect.currentframe().f_back.f_lineno}.")
        self.dbPath = dbPath
        self.data = None

        # Check if the specified directory exists, error if not
        if not self.dbPath.parent.exists():
            if not create_if_missing:
                logger.error(f"Directory '{self.dbPath.parent}' does not exist for database path '{self.dbPath}'")
                raise FileNotFoundError(f"Directory '{self.dbPath.parent}' does not exist for database path '{self.dbPath}'")
            else:
                self.dbPath.parent.mkdir(parents=True, exist_ok=True)
                self.prime()  # Create an empty database file if we're creating the directory

    def load(self) -> None:
        """
        Load the database from the file into memory (private variable).
        """
        if not self.dbPath.exists():
            self.data = {}
            return

        with open(self.dbPath, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def unload(self) -> None:
        """
        Unload the database from memory (private variable).
        """

        # Save current data to file before unloading
        with open(self.dbPath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

        self.data = None


    def prime(self) -> None:
        """
        Creates data inside database that gets the database minimally functional. Usually just a {}.
        """
        self.data = {}
        with open(self.dbPath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

    def fetchEntry(self, key: str):
        """
        Getter method that fetches the data at a specific directory inside the database.

        Assume the database class has already been instantiated with the loaded data being:

        ```
        {
            "example1": "apple",
            "example2": "banana",
            "complex1": {
                "example1": "cherry"
            }
        }
        ```

        If you wanted to fetch a root entry called 'example1', provide argument 'key'. This results in the data associated with 'apple' being returned. 
        If it has multiple values, it is up to you to parse the remaining with the python library 'json'.

        You can go further by specifying complex keys using dot notation. For example, to get 'cherry', you would provide 'complex1.example1' as the key.
        """
        data = self.data

        if data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        
        keys = key.split(".")
        for k in keys:
            if k in data:
                data = data[k]
            else:
                return None
        return data

    def setEntry(self, key: str, value) -> None:
        """
        Setter method that sets the data at a specific directory inside the database.
        """
        if self.data is None:
            raise databaseIsUnloadedError(
                "Database has not been loaded. Please call load() before accessing entries."
            )

        data = self.data
        keys = key.split(".")

        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]

        data[keys[-1]] = value
        


    def deleteEntry(self, key: str) -> None:
        """
        Deleter method that deletes data at a specific directory inside the database.
        """
        data = self.data

        if data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")

        keys = key.split(".")
        for k in keys[:-1]:
            if k not in data:
                return
            data = data[k]

        if keys[-1] in data:
            del data[keys[-1]]

    def addEntry(self, key: str, value) -> None:
        """
        Adds a new entry at a specific directory inside the database.

        Raises an error if the key already exists.
        """
        if self.data is None:
            raise databaseIsUnloadedError(
                "Database has not been loaded. Please call load() before accessing entries."
            )

        data = self.data
        keys = key.split(".")

        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            elif not isinstance(data[k], dict):
                raise TypeError(
                    f"Cannot create subkey under non-dictionary value at '{k}'"
                )
            data = data[k]

        final_key = keys[-1]

        if final_key in data:
            raise KeyError(f"Entry '{key}' already exists")

        data[final_key] = value


    def exists(self, key: str) -> bool:
        """
        Existence checker method that checks if a specific directory inside the database exists.
        """
        data = self.data

        if data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        
        keys = key.split(".")
        for k in keys:
            if k in data:
                data = data[k]
            else:
                return False
        return True
    


class protectedDB:
    """
    Encrypted database class for secure data storage.

    Uses AES-GCM to encrypt the entire JSON blob at rest.
    In-memory, data is stored as a standard Python dict.

    Threat Model:
    - Encryption at rest with authenticated encryption (AES-GCM)
    - Tamper detection via GCM auth tag. Corrupted or modified files will raise ValueError on load
    - Per-file random salt (scrypt), preventing rainbow-table / multi-target attacks across databases
    - Does NOT protect against memory scraping or runtime attacks
    - Volatile in-memory data. Unload asap after making changes to minimize risk.
    - Assumes server environment is trusted

    File layout (v2): [salt: 16 bytes][nonce: 12 bytes][tag: 16 bytes][ciphertext: n bytes]
    Legacy layout (v1, static salt): [nonce: 12 bytes][tag: 16 bytes][ciphertext: n bytes]

    # Methods:
    - load(): Load the database from the file into memory (private variable).
    - unload(): Unload the database from memory (private variable).
    - prime(): Creates data inside database that gets the database minimally functional. Usually just a {}.
    - fetchEntry(key: str): Getter method that fetches the data at a specific directory inside the database.
    - setEntry(key: str, value): Setter method that sets the data at a specific directory inside the database.
    - deleteEntry(key: str): Deleter method that deletes the data at a specific directory inside the database.
    - addEntry(key: str, value): Adds a new entry at a specific directory inside the database.
    - exists(key: str): Existence checker method that checks if a specific directory inside the database exists.
    """

    _SALT_LEN = 16
    _NONCE_LEN = 12
    _TAG_LEN = 16

    # Legacy static salt, kept ONLY to allow reading/migrating old v1 files.
    _LEGACY_SALT = b'nexaDB-salt-K9ui9pyWwfR9T1H1XiHz'

    def __init__(self, dbPath: Path, password: str, create_if_missing: bool = False):
        logger.info(f"Protected Database construction invoked by {inspect.currentframe().f_back.f_globals['__name__']}.{inspect.currentframe().f_back.f_code.co_name}() at line {inspect.currentframe().f_back.f_lineno}.")
        self.dbPath = dbPath
        self.password = password
        self.data = None
        self._salt = None  # set during load()/prime(), NOT derived up front anymore

        # Check if the specified directory exists, error if not
        if not self.dbPath.parent.exists():
            if not create_if_missing:
                logger.error(f"Directory '{self.dbPath.parent}' does not exist for database path '{self.dbPath}'")
                raise FileNotFoundError(f"Directory '{self.dbPath.parent}' does not exist for database path '{self.dbPath}'")
            else:
                self.dbPath.parent.mkdir(parents=True, exist_ok=True)
                self.prime()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 32-byte AES key from the password using scrypt.
        scrypt provides memory-hard key stretching, making brute-force attacks significantly more expensive
        than raw SHA256.
        """
        return scrypt(
            password.encode("utf-8"),
            salt=salt,
            key_len=32,
            N=2**14,  # CPU/memory cost factor
            r=8,       # Block size
            p=1        # Parallelization factor
        )

    def load(self) -> None:
        """
        Load and decrypt database into memory.
        Raises ValueError if the file has been tampered with or the password is incorrect.
        """
        if not self.dbPath.exists():
            self._salt = get_random_bytes(self._SALT_LEN)
            self.data = {}
            return

        with open(self.dbPath, "rb") as f:
            raw = f.read()

        # Try v2 layout first: salt + nonce + tag + ciphertext
        min_v2_len = self._SALT_LEN + self._NONCE_LEN + self._TAG_LEN
        if len(raw) >= min_v2_len:
            salt = raw[:self._SALT_LEN]
            nonce = raw[self._SALT_LEN:self._SALT_LEN + self._NONCE_LEN]
            tag = raw[self._SALT_LEN + self._NONCE_LEN:min_v2_len]
            ciphertext = raw[min_v2_len:]

            key = self._derive_key(self.password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                self._salt = salt
                self.data = json.loads(plaintext)
                return
            except ValueError:
                pass  # fall through and try legacy layout below

        # Fall back to legacy v1 layout: nonce + tag + ciphertext, static salt
        min_v1_len = self._NONCE_LEN + self._TAG_LEN
        if len(raw) < min_v1_len:
            raise ValueError("Encrypted file too short or corrupted")

        nonce = raw[:self._NONCE_LEN]
        tag = raw[self._NONCE_LEN:min_v1_len]
        ciphertext = raw[min_v1_len:]

        key = self._derive_key(self.password, self._LEGACY_SALT)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Database integrity check failed. File may be corrupted or tampered with, or the password is incorrect.")

        self._salt = self._LEGACY_SALT
        self.data = json.loads(plaintext)
        logger.warning(f"Database at '{self.dbPath}' was loaded using the legacy static-salt format. Call migrate_to_v2() to upgrade it.")

    def migrate_to_v2(self) -> None:
        """
        Upgrades a loaded legacy (static-salt) database to the v2 format by
        generating a fresh random salt and rewriting the file. No-op if the
        database is already on a per-file salt (including a freshly primed one).
        """
        if self.data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before migrating.")
        if self._salt != self._LEGACY_SALT:
            return  # already v2, nothing to do

        self._salt = get_random_bytes(self._SALT_LEN)
        self.unload()  # writes out in v2 layout using the new salt
        self.load()    # reload so self.data / self._salt reflect the migrated file

    def unload(self) -> None:
        """
        Encrypt and save database to file, then clear from memory.
        Always writes in the current (v2) layout: salt + nonce + tag + ciphertext.
        """
        if self.data is None:
            return

        if self._salt is None or self._salt == self._LEGACY_SALT:
            # First-ever save, or saving after a legacy load without explicit
            # migration: generate a fresh per-file salt so we never persist
            # the legacy static salt going forward.
            self._salt = get_random_bytes(self._SALT_LEN)

        key = self._derive_key(self.password, self._salt)
        plaintext = json.dumps(self.data, indent=4).encode("utf-8")
        nonce = get_random_bytes(self._NONCE_LEN)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(self.dbPath, "wb") as f:
            f.write(self._salt + nonce + tag + ciphertext)

        self.data = None

    def prime(self) -> None:
        """
        Creates data inside database that gets the database minimally functional.
        Routes through unload() to ensure the file is written encrypted from the start.
        """
        self._salt = get_random_bytes(self._SALT_LEN)
        self.data = {}
        self.unload()

    def fetchEntry(self, key: str):
        if self.data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        data = self.data
        keys = key.split(".")
        for k in keys:
            if k in data:
                data = data[k]
            else:
                return None
        return data

    def setEntry(self, key: str, value) -> None:
        if self.data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        data = self.data
        keys = key.split(".")
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    def addEntry(self, key: str, value) -> None:
        if self.data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        data = self.data
        keys = key.split(".")
        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            elif not isinstance(data[k], dict):
                raise TypeError(f"Cannot create subkey under non-dictionary value at '{k}'")
            data = data[k]
        final_key = keys[-1]
        if final_key in data:
            raise KeyError(f"Entry '{key}' already exists")
        data[final_key] = value

    def deleteEntry(self, key: str) -> None:
        if self.data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        data = self.data
        keys = key.split(".")
        for k in keys[:-1]:
            if k not in data:
                return
            data = data[k]
        if keys[-1] in data:
            del data[keys[-1]]

    def exists(self, key: str) -> bool:
        if self.data is None:
            raise databaseIsUnloadedError("Database has not been loaded. Please call load() before accessing entries.")
        data = self.data
        keys = key.split(".")
        for k in keys:
            if k in data:
                data = data[k]
            else:
                return False
        return True



class databaseIsUnloadedError(Exception):
    """
    Exception raised when attempting to access the database before it has been loaded.
    """
    pass
