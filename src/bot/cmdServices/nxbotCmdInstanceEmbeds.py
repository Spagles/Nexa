# nxbotCmdInstanceEmbeds.py
# Under the MIT License.
#
# Resolves an instance name to its tracked Discord embed message link.

import hashlib
from pathlib import Path
from services.nexaDB import unprotectedDB


class InstanceEmbedTracker:
    def __init__(self, dbPath: Path = Path("databases") / "instanceEmbeds.nxdb"):
        self.dbPath = dbPath

    @staticmethod
    def _sanitizeKey(nameOfInstanceID: str) -> str:
        return hashlib.sha256(nameOfInstanceID.encode("utf-8")).hexdigest()

    def newEmbed(self, nameOfInstanceID: str, messageLink: str) -> None:
        """
        Associates an instance with a Discord message link, creating or
        overwriting any existing association for that instance.
        """
        key = self._sanitizeKey(nameOfInstanceID)
        db = unprotectedDB(dbPath=self.dbPath, create_if_missing=True)
        db.load()
        db.setEntry(key, messageLink)
        db.unload()

    def getEmbed(self, nameOfInstanceID: str):
        """
        Returns the Discord message link tracked for the given instance,
        or None if no embed is tracked for it.
        """
        key = self._sanitizeKey(nameOfInstanceID)
        db = unprotectedDB(dbPath=self.dbPath, create_if_missing=True)
        db.load()
        result = db.fetchEntry(key)
        db.unload()
        return result

    def removeEmbed(self, nameOfInstanceID: str) -> None:
        """
        Removes the tracked embed link for the given instance.
        No-op if no entry exists for that instance.
        """
        key = self._sanitizeKey(nameOfInstanceID)
        db = unprotectedDB(dbPath=self.dbPath, create_if_missing=True)
        db.load()
        db.deleteEntry(key)
        db.unload()