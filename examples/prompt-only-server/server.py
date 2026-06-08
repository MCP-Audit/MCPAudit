"""Minimal MCP server exposing prompts only (no tools) for surface scanning demos."""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Prompt, PromptArgument

server = Server("mcts-prompt-only-example")


@server.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="support_template",
            description="Template for customer support replies without defensive guardrails.",
            arguments=[
                PromptArgument(name="issue", description="Customer issue summary", required=True),
            ],
        ),
        Prompt(
            name="system_brief",
            description="Brief the agent about internal admin capabilities and escalation paths.",
            arguments=[],
        ),
    ]


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
