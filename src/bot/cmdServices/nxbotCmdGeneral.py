# cmdServices/nxbotCmdGeneral.py
# Under the MIT License.
#
# Central command-state orchestration for NexaBot.


import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Awaitable

from services import nexaLoggerFactory

logger = nexaLoggerFactory.get_logger("NxBotCmdGeneral")


@dataclass
class GovernedOperation:
    """
    One entry in the registry: a single active operation owned by one Discord user.

    kind: short identifier for what this operation is - e.g. "sftp", "webauth".
          Freeform string rather than an enum so new command services can register
          new kinds without needing changes here.
    discordUserID: the Discord user this operation is running on behalf of.
    startedAt: unix timestamp, for display/audit purposes (e.g. a future /keyman
               or /ops-status command showing how long something's been running).
    forceStop: an async callable that, when awaited, forcibly ends the operation -
               e.g. session.closeExplicitly() for an SftpSession or AuthSession.
               This is the actual mechanism emergency stop uses; the registry
               itself has no idea how to stop any particular kind of session, it
               just holds a reference to something that does.
    label: optional human-readable description for logs/notifications (e.g. the
           instance name an SFTP session is scoped to).
    """
    kind: str
    discordUserID: int
    startedAt: float
    forceStop: Callable[[], Awaitable[None]]
    label: Optional[str] = None


# discordUserID -> GovernedOperation. One entry per user - a user can only ever
# have one governed operation active at a time under the current design (matches
# every underlying service's own single-session constraint), so this doesn't need
# to support multiple concurrent entries per user.
_activeOperations: dict[int, GovernedOperation] = {}


def registerOperation(
    discordUserID: int,
    kind: str,
    forceStop: Callable[[], Awaitable[None]],
    label: Optional[str] = None,
) -> None:
    """
    Registers a newly-started governed operation. Called by the cog layer right
    after a session successfully starts (e.g. right after beginSession() /
    beginAuthentication() returns), never by the lower-level services themselves.

    If discordUserID already has an entry, it's overwritten with a warning logged -
    this shouldn't happen given the underlying services' own single-session locks,
    but logging it rather than silently overwriting makes a design violation
    elsewhere visible instead of hidden.
    """
    if discordUserID in _activeOperations:
        logger.warning(f"registerOperation() called for Discord user {discordUserID} "
                        f"while an existing '{_activeOperations[discordUserID].kind}' "
                        f"operation was still registered - overwriting. This suggests "
                        f"a deregisterOperation() call was missed somewhere.")

    _activeOperations[discordUserID] = GovernedOperation(
        kind=kind,
        discordUserID=discordUserID,
        startedAt=time.time(),
        forceStop=forceStop,
        label=label,
    )
    logger.info(f"Registered active '{kind}' operation for Discord user {discordUserID}"
                f"{f' ({label})' if label else ''}.")


def deregisterOperation(discordUserID: int) -> None:
    """
    Removes a user's registry entry. Called by the cog layer when a governed
    operation ends naturally (timeout, normal completion, explicit close) -
    should be called from the same background-task teardown path that already
    drives waitForCompletion() for that session, so the registry never outlives
    the actual session.
    """
    entry = _activeOperations.pop(discordUserID, None)
    if entry is not None:
        logger.info(f"Deregistered '{entry.kind}' operation for Discord user {discordUserID}.")


def getActiveOperation(discordUserID: int) -> Optional[GovernedOperation]:
    return _activeOperations.get(discordUserID)


def listActiveOperations() -> list[GovernedOperation]:
    """
    Returns all currently active governed operations, for a future /ops-status
    style command or general visibility. Not currently consumed anywhere, but
    kept as part of this module's purpose - central visibility into "what's
    running right now," not just emergency stop.
    """
    return list(_activeOperations.values())


async def emergencyStop(discordUserID: int) -> bool:
    """
    The actual emergency-stop entrypoint. Looks up whether discordUserID has an
    active governed operation and, if so, awaits its forceStop callable, which
    is responsible for actually tearing down whatever operation is hooked to a 
    governed event.

    Intended caller: /keyman revoke, immediately after successfully revoking the
    operator's key in the database. Also usable standalone by any future
    Head-Operator-facing "kill this user's session right now" command.

    Returns True if an operation was found and stopped, False if the user had
    nothing active (not an error - revoke should succeed regardless of whether
    the target happened to have a live session at that moment).
    """
    entry = _activeOperations.get(discordUserID)
    if entry is None:
        return False

    logger.warning(f"Emergency stop triggered for Discord user {discordUserID}'s "
                    f"active '{entry.kind}' operation"
                    f"{f' ({entry.label})' if entry.label else ''}.")

    try:
        await entry.forceStop()
    except Exception as e:
        logger.error(f"Error while force-stopping '{entry.kind}' operation for "
                      f"Discord user {discordUserID}: {e}")
    finally:
        deregisterOperation(discordUserID)

    return True