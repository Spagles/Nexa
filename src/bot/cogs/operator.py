# cogs/operator.py
# Under the MIT License.
#
# Bot commands exclusively reserved for server operators.

import os
import base64
import io
from pathlib import Path
from typing import List
import asyncio

import discord
from discord.ext import commands
from discord import app_commands, Interaction

from services.nexaDB import protectedDB
from services.nexaConfig import NexaConfig
from services.nexaAuthenticationService import (
    NexaAuthenticationService,
    OperatorKeyAlreadyExistsError,
    OperatorKeyNotFoundError,
    InvalidCapabilityError,
)
from services.nexaVerifService import NexaVerifService
from services.nexaSftpService import NexaSftpService, SESSION_TIMEOUT_SECONDS
from services import nexaLoggerFactory

from ..cmdServices import nxbotCmdGeneral

from ..ui import SimpleMenu, MenuButton

logger = nexaLoggerFactory.get_logger("OperatorCog")


# Head Operator ticket info
TICKET_LIFETIME_SECONDS = 15 * 60
_headOperatorTicketExpiresAt: float = 0.0  # 0.0 / any past timestamp = no valid ticket


def _hasValidTicket() -> bool:
    global _headOperatorTicketExpiresAt
    import time
    if time.time() >= _headOperatorTicketExpiresAt:
        _headOperatorTicketExpiresAt = 0.0  # explicitly zero out an expired ticket
        return False
    return True


def _issueTicket() -> None:
    global _headOperatorTicketExpiresAt
    import time
    _headOperatorTicketExpiresAt = time.time() + TICKET_LIFETIME_SECONDS


def _buildAuthService(config: NexaConfig, notificationService: NotificationHelper) -> NexaAuthenticationService:
    """
    Constructs a fresh protectedDB + NexaAuthenticationService pair pointed at keys.nxdb.
    Instantiation is normalized to CWD, so this works identically wherever it's called from.

    config: the bot's NexaConfig instance (self.bot.config), passed through to
            NexaAuthenticationService as configClass.
    """
    db_key = os.environ.get("NEXABOT_PROTECTED_KEY")
    keySystem = protectedDB(
        dbPath=Path("databases") / "keys.nxdb",
        password=db_key,
        create_if_missing=True
    )
    return NexaAuthenticationService(protectedDB=keySystem, configClass=config, notifier=notificationService)



async def _ensureHeadOperatorTicket(interaction: Interaction, verifService: NexaVerifService) -> bool:
    """
    Called by every /keyman subcommand immediately after the existing check_terms /
    check_operator / check_head_operator gates, and BEFORE the command does anything
    else with the interaction. This function always defers the interaction itself
    (ephemeral), so callers must use interaction.followup.send(...) for their own
    responses afterward, never interaction.response.send_message(...) - this keeps
    the response pattern uniform regardless of whether a ticket was already valid
    or a full verification flow had to run.

    verifService must be the cog's single, shared NexaVerifService instance (e.g.
    self.verifService), not a freshly constructed one. Its single-active-session
    lock only means anything if every caller shares the same instance.

    If a valid ticket is already held, defers and returns True immediately with no
    further user-visible action. Otherwise, walks the Head Operator through the same
    web-auth workflow used elsewhere (isHOVerif=True, so it checks the root key
    specifically, never an operator code).

    Returns False if verification fails, times out, or a session is already active
    for some other reason; in every False case, this function has already edited the
    deferred response to explain why, so the caller should simply return.
    """
    await interaction.response.defer(ephemeral=True)

    if _hasValidTicket():
        return True

    try:
        session = await verifService.beginAuthentication(
            discordUserID=interaction.user.id,
            isHOVerif=True
        )
    except RuntimeError as e:
        await interaction.followup.send(str(e), ephemeral=True)
        return False

    embed = discord.Embed(
        title="Head Operator Verification Required",
        description=(
            f"Your /keyman session has expired or has not yet been verified this session. "
            f"Open this link or scan the QR code below, then submit your Head Operator "
            f"authentication code to continue.\n\n"
            f"**Link:** {session.tunnelUrl}"
        ),
        color=discord.Color.gold()
    )
    embed.set_image(url="attachment://qr.png")
    embed.set_footer(text="This verification will time out automatically if left idle.")

    qrBytes = base64.b64decode(session.qrCodeDataUri.split(",", 1)[1])
    qrFile = discord.File(io.BytesIO(qrBytes), filename="qr.png")

    message = await interaction.followup.send(embed=embed, file=qrFile, ephemeral=True, wait=True)

    logger.info(f"Head Operator ticket verification started by {interaction.user.id}.")

    result = await verifService.endSession(session)

    if not result.success:
        logger.warning(f"Head Operator ticket verification failed for {interaction.user.id}: {result.reason}")
        failedEmbed = discord.Embed(
            title="Verification Failed",
            description=f"Could not verify your Head Operator credential.\n\n**Reason:** `{result.reason}`\n\n"
                        f"Run the command again to retry.",
            color=discord.Color.red()
        )
        await message.edit(embed=failedEmbed, attachments=[])
        return False

    _issueTicket()
    logger.info(f"Head Operator ticket issued for {interaction.user.id}, valid for "
                f"{TICKET_LIFETIME_SECONDS // 60} minutes.")

    confirmedEmbed = discord.Embed(
        title="Verified",
        description=f"You're verified for the next {TICKET_LIFETIME_SECONDS // 60} minutes. Continuing...",
        color=discord.Color.green()
    )
    await message.edit(embed=confirmedEmbed, attachments=[])
    return True


async def _ensureOpHasCorrectPerms(
    interaction: Interaction,
    verifService: NexaVerifService,
    permissions: List[str],
) -> bool:
    """
    Defers the interaction, verifies the caller through the web-auth flow,
    and returns True only if the verified operator holds every requested permission.

    verifService must be the cog's single, shared NexaVerifService instance (e.g.
    self.verifService). See _ensureHeadOperatorTicket's docstring for why.
    """
    await interaction.response.defer(ephemeral=True)

    if not permissions:
        return True

    try:
        session = await verifService.beginAuthentication(
            discordUserID=interaction.user.id
        )
    except RuntimeError as e:
        await interaction.followup.send(str(e), ephemeral=True)
        return False

    embed = discord.Embed(
        title="Operator Verification Required",
        description=(
            "Your operator permissions need to be verified before you can continue. "
            "Open this link or scan the QR code below, then submit a valid "
            "operator authentication code to proceed.\n\n"
            f"**Link:** {session.tunnelUrl}"
        ),
        color=discord.Color.blurple()
    )
    embed.set_image(url="attachment://qr.png")
    embed.set_footer(text="This verification will time out automatically if left idle.")

    qrBytes = base64.b64decode(session.qrCodeDataUri.split(",", 1)[1])
    qrFile = discord.File(io.BytesIO(qrBytes), filename="qr.png")

    message = await interaction.followup.send(embed=embed, file=qrFile, ephemeral=True, wait=True)

    logger.info(f"Operator permission verification started by {interaction.user.id}.")

    result = await verifService.endSession(session)

    if not result.success:
        logger.warning(f"Operator permission verification failed for {interaction.user.id}: {result.reason}")
        failedEmbed = discord.Embed(
            title="Verification Failed",
            description=(
                f"Could not verify your operator credentials.\n\n**Reason:** `{result.reason}`\n\n"
                f"Run the command again to retry."
            ),
            color=discord.Color.red()
        )
        await message.edit(embed=failedEmbed, attachments=[])
        return False

    missingPermissions = [p for p in permissions if p not in result.capabilities]
    if missingPermissions:
        # Kept this in just in case I want to show permissions required in the future
        # missingDisplay = ", ".join(f"`{p}`" for p in missingPermissions)
        deniedEmbed = discord.Embed(
            title="Insufficient Permissions",
            description=f"Your verified operator key is missing the required permissions for this command.",
            color=discord.Color.orange()
        )
        await message.edit(embed=deniedEmbed, attachments=[])
        return False

    confirmedEmbed = discord.Embed(
        title="Verified",
        description="Your operator permissions are sufficient for this action.",
        color=discord.Color.green()
    )
    await message.edit(embed=confirmedEmbed, attachments=[])
    return True


def _resolve_instance_folder(bot, instance_name: str | None) -> Path:
    if instance_name:
        instance = bot.instance_manager.get_instance(instance_name)
        if instance is None:
            raise ValueError(f"Instance '{instance_name}' was not found.")
        return Path(instance.folder).expanduser().resolve()

    configured_name = bot.config.get("general.primaryInstance")
    if configured_name:
        instance = bot.instance_manager.get_instance(configured_name)
        if instance is not None:
            return Path(instance.folder).expanduser().resolve()

    primary_instance = bot.instance_manager.get_primary_instance()
    if primary_instance is not None:
        return Path(primary_instance.folder).expanduser().resolve()

    raise ValueError("No instance was specified and no primary instance is configured.")


class _HeadOperatorApprovalView(discord.ui.View):
    def __init__(self, timeout_seconds: int = 60):
        super().__init__(timeout=timeout_seconds)
        self.approved = asyncio.Event()
        self.denied = asyncio.Event()

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.success)
    async def approve(self, interaction: Interaction, _button: discord.ui.Button):
        self.approved.set()
        self.stop()
        await interaction.response.send_message("Approved.", ephemeral=True)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
    async def deny(self, interaction: Interaction, _button: discord.ui.Button):
        self.denied.set()
        self.stop()
        await interaction.response.send_message("Denied.", ephemeral=True)

class OperatorCog(commands.Cog):
    """Discord commands for operators."""

    def __init__(self, bot: "NexaBot"):  # type: ignore
        self.bot = bot
        self.notifService = NotificationHelper(bot=self.bot)

        # Constructed once for the cog's lifetime, not per-command-invocation. 
        self.authService = _buildAuthService(self.bot.config, notificationService=self.notifService)
        self.verifService = NexaVerifService(self.authService)
        self.sftpService = NexaSftpService(authService=self.authService)

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _instance_choices(self) -> list[app_commands.Choice[str]]:
        return [
            app_commands.Choice(name=n, value=n)
            for n in self.bot.instance_manager.instances.keys()
        ]

    async def _instance_autocomplete(self, interaction: Interaction, current: str):
        return [
            app_commands.Choice(name=n, value=n)
            for n in self.bot.instance_manager.instances.keys()
            if current.lower() in n.lower()
        ]

    async def _awaitSftpSessionTeardown(self, session) -> None:
        try:
            outcome = await self.sftpService.endSession(session)
            logger.info(f"SFTP session for Discord user {session.discordUserID} ended: {outcome.reason}")
        except Exception as e:
            logger.error(f"Error while tearing down SFTP session for Discord user "
                         f"{session.discordUserID}: {e}")
        finally:
            nxbotCmdGeneral.deregisterOperation(session.discordUserID)

    # ------------------------------------------------------------------
    # /keyman command group - Head Operator only
    # ------------------------------------------------------------------

    keyman_group = app_commands.Group(
        name="keyman",
        description="Manage authentication keys for Server Operators."
    )

    @keyman_group.command(name="issue", description="Issue a new operator key with the given capability.")
    @app_commands.describe(
        discord_user="The Server Operator to issue a key to.",
        capability="The capability to grant on this key."
    )
    @app_commands.choices(capability=[
        app_commands.Choice(name="File System Access", value="fsaccess"),
        app_commands.Choice(name="Modpack Installs", value="modpackInstalls"),
    ])
    async def issue(self, interaction: Interaction, discord_user: discord.User, capability: app_commands.Choice[str]):
        if not await self.bot.check_terms(interaction):
            return
        if not await self.bot.check_operator(interaction):
            return
        if not await self.bot.check_head_operator(interaction):
            return


        if not await _ensureHeadOperatorTicket(interaction, self.verifService):
            return

        if not self.bot._is_server_operator(discord_user.id):
            await interaction.followup.send(
                f"{discord_user.mention} is not a Server Operator. Operator keys can only be "
                f"issued to users listed under `security.serverOperators`. Add them there first "
                f"if this was intentional.",
                ephemeral=True
            )
            return

        try:
            code = self.authService.issueOperatorKey(
                discordUserID=discord_user.id,
                capabilities=[capability.value]
            )
        except OperatorKeyAlreadyExistsError:
            await interaction.followup.send(
                f"{discord_user.mention} already has an active operator key. "
                f"Use `/keyman modify` to change their capabilities, `/keyman rotate` to reissue "
                f"their code, or `/keyman revoke` first if you want to start over.",
                ephemeral=True
            )
            return
        except InvalidCapabilityError as e:
            await interaction.followup.send(str(e), ephemeral=True)
            return

        logger.info(f"Operator key issued to Discord user {discord_user.id} "
                    f"by Head Operator {interaction.user.id}. Capability: {capability.value}")

        await interaction.followup.send(
            f"Key issued for {discord_user.mention} with capability `{capability.value}`.\n\n"
            f"**Code:** `{code}`\n\n"
            f"This code is shown only once and is not stored anywhere in plaintext. "
            f"Share it directly and securely with {discord_user.mention}, and instruct them "
            f"to save it somewhere safe. It cannot be recovered or displayed again. "
            f"If it's ever lost or suspected leaked, use `/keyman rotate` to issue a replacement.",
            ephemeral=True
        )

    @keyman_group.command(name="modify", description="Add or remove a single capability on an operator's existing key.")
    @app_commands.describe(
        discord_user="The Server Operator whose key you're modifying.",
        capability="The capability to add or remove.",
        action="Whether to add or remove the capability."
    )
    @app_commands.choices(
        capability=[
            app_commands.Choice(name="File System Access", value="fsaccess"),
            app_commands.Choice(name="Modpack Installs", value="modpackInstalls"),
        ],
        action=[
            app_commands.Choice(name="Add", value="add"),
            app_commands.Choice(name="Remove", value="remove"),
        ]
    )
    async def modify(
        self,
        interaction: Interaction,
        discord_user: discord.User,
        capability: app_commands.Choice[str],
        action: app_commands.Choice[str]
    ):
        if not await self.bot.check_terms(interaction):
            return
        if not await self.bot.check_operator(interaction):
            return
        if not await self.bot.check_head_operator(interaction):
            return

        if not await _ensureHeadOperatorTicket(interaction, self.verifService):
            return

        if not self.bot._is_server_operator(discord_user.id):
            logger.warning(f"{discord_user.id} holds an operator key but is no longer listed as a "
                            f"Server Operator. Consider using /keyman revoke instead of modifying.")

        try:
            updatedCapabilities = self.authService.modifyOperatorKey(
                discordUserID=discord_user.id,
                capability=capability.value,
                action=action.value
            )
        except OperatorKeyNotFoundError:
            await interaction.followup.send(
                f"{discord_user.mention} does not have an active operator key. "
                f"Use `/keyman issue` first.",
                ephemeral=True
            )
            return
        except InvalidCapabilityError as e:
            await interaction.followup.send(str(e), ephemeral=True)
            return

        logger.info(f"Operator key for Discord user {discord_user.id} modified "
                    f"by Head Operator {interaction.user.id}: {action.value} {capability.value}")

        capabilitiesDisplay = ", ".join(f"`{c}`" for c in updatedCapabilities) if updatedCapabilities else "*(none)*"
        await interaction.followup.send(
            f"Updated capabilities for {discord_user.mention}: {capabilitiesDisplay}",
            ephemeral=True
        )

    @keyman_group.command(name="revoke", description="Revoke an operator's key entirely.")
    @app_commands.describe(discord_user="The Server Operator whose key you're revoking.")
    async def revoke(self, interaction: Interaction, discord_user: discord.User):
        if not await self.bot.check_terms(interaction):
            return
        if not await self.bot.check_operator(interaction):
            return
        if not await self.bot.check_head_operator(interaction):
            return

        if not await _ensureHeadOperatorTicket(interaction, self.verifService):
            return

        try:
            self.authService.revokeOperatorKey(discordUserID=discord_user.id)
        except OperatorKeyNotFoundError:
            await interaction.followup.send(
                f"{discord_user.mention} does not have an active operator key to revoke.",
                ephemeral=True
            )
            return

        logger.info(f"Operator key for Discord user {discord_user.id} revoked "
                    f"by Head Operator {interaction.user.id}.")

        # Works as a hook to detect key revocation that invalidates any current
        # operation for safety.
        wasStopped = await nxbotCmdGeneral.emergencyStop(discord_user.id)
        if wasStopped:
            logger.warning(f"Revocation of Discord user {discord_user.id}'s key also "
                            f"force-stopped an active operation in progress under that "
                            f"credential.")

        stoppedNote = (
            "\n\nThey also had an active session in progress, which has been immediately terminated."
            if wasStopped else ""
        )
        await interaction.followup.send(
            f"Revoked the operator key for {discord_user.mention}.{stoppedNote}",
            ephemeral=True
        )

    @keyman_group.command(name="rotate", description="Revoke and reissue an operator's key, carrying over their capabilities.")
    @app_commands.describe(discord_user="The Server Operator whose key you're rotating.")
    async def rotate(self, interaction: Interaction, discord_user: discord.User):
        if not await self.bot.check_terms(interaction):
            return
        if not await self.bot.check_operator(interaction):
            return
        if not await self.bot.check_head_operator(interaction):
            return

        if not await _ensureHeadOperatorTicket(interaction, self.verifService):
            return

        if not self.bot._is_server_operator(discord_user.id):
            await interaction.followup.send(
                f"{discord_user.mention} is not a Server Operator. If they no longer should have "
                f"access, use `/keyman revoke` instead. If this is unexpected, confirm they're "
                f"listed under `security.serverOperators`.",
                ephemeral=True
            )
            return

        try:
            newCode = self.authService.rotateOperatorKey(discordUserID=discord_user.id)
        except OperatorKeyNotFoundError:
            await interaction.followup.send(
                f"{discord_user.mention} does not have an active operator key to rotate.",
                ephemeral=True
            )
            return

        logger.info(f"Operator key for Discord user {discord_user.id} rotated "
                    f"by Head Operator {interaction.user.id}.")

        await interaction.followup.send(
            f"Key rotated for {discord_user.mention}. Their previous code is no longer valid.\n\n"
            f"**New Code:** `{newCode}`\n\n"
            f"This code is shown only once and is not stored anywhere in plaintext. "
            f"Share it directly and securely with {discord_user.mention}, and instruct them "
            f"to save it somewhere safe - it cannot be recovered or displayed again.",
            ephemeral=True
        )

    @keyman_group.command(name="list", description="List active operator keys and their capabilities.")
    @app_commands.describe(discord_user="Optional: filter to a specific Server Operator.")
    async def list_keys(self, interaction: Interaction, discord_user: discord.User = None):
        if not await self.bot.check_terms(interaction):
            return
        if not await self.bot.check_operator(interaction):
            return
        if not await self.bot.check_head_operator(interaction):
            return

        if not await _ensureHeadOperatorTicket(interaction, self.verifService):
            return

        targetID = discord_user.id if discord_user else None
        entries = self.authService.listOperatorKeys(discordUserID=targetID)

        if not entries:
            message = (
                f"{discord_user.mention} has no active operator key."
                if discord_user else
                "There are no active operator keys."
            )
            await interaction.followup.send(message, ephemeral=True)
            return

        menu = SimpleMenu(interaction.user)

        if len(entries) == 1 or discord_user is not None:
            for entry in entries:
                capabilitiesDisplay = ", ".join(f"`{c}`" for c in entry["capabilities"]) if entry["capabilities"] else "*(none)*"
                menu.add_page(
                    title=f"Operator Key: <@{entry['discordUserID']}>",
                    description=(
                        f"**Discord User:** <@{entry['discordUserID']}>\n"
                        f"**Capabilities:** {capabilitiesDisplay}\n"
                        f"**Issued On:** {entry['issuedOn']}"
                    )
                )
        else:
            lines = []
            for entry in entries:
                capabilitiesDisplay = ", ".join(entry["capabilities"]) if entry["capabilities"] else "(none)"
                lines.append(f"<@{entry['discordUserID']}> - {capabilitiesDisplay}")
            menu.add_page(
                title="Active Operator Keys",
                description="\n".join(lines)
            )

        # already_deferred=True: _ensureHeadOperatorTicket() above always defers this
        # interaction before this point, so SimpleMenu must use followup.send() rather
        # than response.send_message() here.
        await menu.send(interaction, already_deferred=True)


    # Filesystem Access Command
    @app_commands.command(name="fsaccess", description="[OPS] Grants Filesystem Access to an instance")
    @app_commands.describe(instance="The instance to open filesystem access to.")
    @app_commands.autocomplete(instance=_instance_autocomplete)
    async def filesystem_access(self, interaction: Interaction, instance: str | None = None):
        if not await self.bot.check_terms(interaction):
            return
        if not await self.bot.check_operator(interaction):
            return

        # This pipes into the Nexa Authentication step
        if not await _ensureOpHasCorrectPerms(interaction, self.verifService, ["fsaccess"]):
            return

        try:
            jail_root = _resolve_instance_folder(self.bot, instance)
        except ValueError as exc:
            logger.error(f"An error occured while setting up the SFTP Connection: {str(exc)}")
            await interaction.followup.send("An error occurred.", ephemeral=True)
            return

        require_approval = self.bot.config.get("security.requireHeadOperatorApprovalForHighLevelOperation", True)
        if require_approval:
            head_operator_id = self.bot.config.get("security.headOperator", 0)
            if head_operator_id:
                head_user = await self.bot.fetch_user(head_operator_id)
                if head_user is None:
                    await interaction.followup.send("The configured Head Operator could not be resolved.", ephemeral=True)
                    return

                APPROVAL_TIMEOUT_SECONDS = 300  # 5 mins

                view = _HeadOperatorApprovalView(timeout_seconds=APPROVAL_TIMEOUT_SECONDS)
                await head_user.send(
                    f"Operator <@{interaction.user.id}> requested temporary filesystem access to '{jail_root.name}'.",
                    view=view,
                )

                await interaction.followup.send(
                    embed=discord.Embed(
                        title="Awaiting Head Operator Approval",
                        description=(
                            "Your filesystem access request is currently being presented "
                            "to the Head Operator for approval. This page will not update "
                            "automatically - you'll receive a new message once a decision "
                            "is made."
                        ),
                        color=discord.Color.blurple()
                    ),
                    ephemeral=True
                )

                # Wait on BOTH approved and denied together, not just approved.
                approvedTask = asyncio.create_task(view.approved.wait())
                deniedTask = asyncio.create_task(view.denied.wait())
                try:
                    done, pending = await asyncio.wait(
                        {approvedTask, deniedTask},
                        timeout=APPROVAL_TIMEOUT_SECONDS,
                        return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    for task in (approvedTask, deniedTask):
                        if not task.done():
                            task.cancel()

                if not done:
                    await interaction.followup.send("Head Operator approval timed out.", ephemeral=True)
                    return

                if view.denied.is_set():
                    await interaction.followup.send("Head Operator denied the request.", ephemeral=True)
                    return

        try:
            session = await self.sftpService.beginSession(str(jail_root), interaction.user.id)
        except RuntimeError as exc:
            await interaction.followup.send(str(exc), ephemeral=True)
            return

        nxbotCmdGeneral.registerOperation(
            discordUserID=interaction.user.id,
            kind="sftp",
            forceStop=session.closeExplicitly,
            label=jail_root.name,
        )

        asyncio.create_task(self._awaitSftpSessionTeardown(session))

        key_bytes = session.privateKeyPem.encode("utf-8") if session.privateKeyPem else b""
        await interaction.user.send(
            embed=discord.Embed(
                title="SFTP Access Ready",
                description=(
                    f"Temporary access is ready for the instance folder `{jail_root}`.\n\n"
                    f"Host: `{session.tunnelHost}`\n"
                    f"Port: `{session.tunnelPort}`\n"
                    f"Username: `nexa`\n"
                    f"Timeout: `{SESSION_TIMEOUT_SECONDS // 60} minutes`"
                ),
                color=discord.Color.green(),
            ),
            file=discord.File(io.BytesIO(key_bytes), filename="nexa_sftp_key.pem"),
            delete_after=90.0
        )

        await interaction.followup.send(
            "Your temporary SFTP access details were sent to your DMs. Access this and download your data immediately. The details will be deleted in 90 seconds.",
            ephemeral=True,
        )


class NotificationHelper:
    def __init__(self, bot: "NexaBot"): #type: ignore
        self.bot = bot

    async def dmHeadOperator(self, message: str) -> None:
        head_operator_id = self.bot.config.get("security.headOperator", 0)
        if not head_operator_id:
            logger.warning("Head operator ID is not configured.")
            return

        user = await self._fetch_user(head_operator_id)
        if user is None:
            logger.warning(f"Head operator user {head_operator_id} could not be resolved.")
            return

        await self._send_dm(user, message)

    async def dmAllOperators(self, message: str) -> None:
        print("Sending DM to all Operators")
        operator_ids = set(self.bot.config.get("security.serverOperators", []) or [])
        head_operator_id = self.bot.config.get("security.headOperator", 0)
        print(f"operator_ids: {operator_ids}")
        print(f"head_operator_id: {head_operator_id}")
        if head_operator_id:
            operator_ids.add(head_operator_id)

        for user_id in operator_ids:
            user = await self._fetch_user(user_id)
            if user is not None:
                print(f"sending a DM to {user}")
                await self._send_dm(user, message)

    async def _fetch_user(self, user_id: int) -> discord.User | None:
        try:
            return await self.bot.fetch_user(user_id)
        except discord.NotFound:
            return None
        except discord.HTTPException as exc:
            logger.warning(f"Failed to fetch user {user_id}: {exc}")
            return None

    async def _send_dm(self, user: discord.User, message: str) -> None:
        try:
            await user.send(message)
        except discord.Forbidden:
            logger.warning(f"Cannot DM user {user.id}; DMs are closed.")
        except discord.HTTPException as exc:
            logger.warning(f"Failed to DM user {user.id}: {exc}")


async def setup(bot: "NexaBot"):  # type: ignore
    await bot.add_cog(OperatorCog(bot))