"""
nxbotGuard.py

Centralized permission/authentication guard for Nexa's Discord command
surface. Replaces the pattern of chaining individual check_x() calls at
every command's execute() site (guild check duplicated per call, multiple
interaction.response calls on the same interaction, no single source of
truth for what a command actually requires).

evaluate() is the single entrypoint: it looks up a command's requirements
from NexaCmdConfig, runs exactly the checks that apply, and guarantees at
most one interaction.response call regardless of how many checks are
involved or which one fails.
"""

import logging
from typing import Optional

from discord import Interaction

from services.nexaConfig import NexaCmdConfig, PermissionLevel

logger = logging.getLogger(__name__)


class NxbotGuard:
    def __init__(self, bot, cmdConfig: NexaCmdConfig):
        self.bot = bot
        self.cmdConfig = cmdConfig
 
    async def evaluate(self, interaction: Interaction, command: str) -> bool:
        """
        Runs, in order: guild check -> enabled check -> terms check ->
        permission-level check. Short-circuits on first failure. Sends
        exactly one interaction response total (guild/enabled/permission
        failures respond directly; a terms failure delegates to
        bot.check_terms(), which sends its own menu).
 
        Returns True if every check passed and the caller should proceed.

        Returns False if any check failed; the guard has already handled
        messaging the user, so the caller should just `return`.
        """
        if not await self._checkGuild(interaction):
            return False
 
        if not self.cmdConfig.isEnabled(command):
            await interaction.response.send_message("Unknown command.", ephemeral=True)
            logger.info(f"Blocked disabled command '{command}' invoked by {interaction.user} ({interaction.user.id}).")
            return False
 
        if not await self.bot.check_terms(interaction):
            return False
 
        requiredLevel = self.cmdConfig.getPermissionLevel(command)
        if requiredLevel is not None and not await self._checkPermissionLevel(interaction, command, requiredLevel):
            return False
 
        return True
 
    async def _checkGuild(self, interaction: Interaction) -> bool:
        if self.bot._is_authorized_guild(interaction.guild_id):
            return True
        await interaction.response.send_message(
            "This bot is not authorized for use in this server.", ephemeral=True
        )
        logger.warning(f"Unauthorized guild access attempt by {interaction.user} ({interaction.user.id}) in guild {interaction.guild_id}.")
        return False
 
    async def _checkPermissionLevel(self, interaction: Interaction, command: str, required: PermissionLevel) -> bool:
        userLevel = self._resolveUserLevel(interaction.user.id)
 
        if userLevel >= required:
            return True
 
        await interaction.response.send_message(
            "You do not have permission to use this command.", ephemeral=True
        )
        logger.warning(
            f"Permission denied for '{command}': user {interaction.user} ({interaction.user.id}) "
            f"has level {userLevel.name}, requires {required.name}."
        )
        return False
 
    def _resolveUserLevel(self, user_id: int) -> PermissionLevel:
        """
        Resolves a user's highest applicable PermissionLevel, checked from
        the top down. This is what makes a Head-Operator-only user (not
        separately listed under security.serverOperators) still pass an
        OPERATOR-level requirement -- the exact failure mode the old
        check_operator() -> check_head_operator() chain was vulnerable to.
        """
        if self.bot._is_head_operator(user_id):
            return PermissionLevel.HEAD_OPERATOR
        if self.bot._is_server_operator(user_id):
            return PermissionLevel.OPERATOR
        if self.bot._is_superuser(user_id):
            return PermissionLevel.SUPERUSER
        return PermissionLevel.EVERYONE
