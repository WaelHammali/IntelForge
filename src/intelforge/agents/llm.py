"""Provider-agnostic chat-model factory and a thin completion helper."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from intelforge.config import settings

Role = str  # "cleaner" | "analyst" | "researcher"


@lru_cache(maxsize=8)
def chat_model(role: Role) -> BaseChatModel:
    """Build (and cache) the chat model configured for ``role``.

    The model string uses LangChain's ``provider:model`` form, so any
    provider ``init_chat_model`` supports works without code changes.
    """
    spec = settings.role_model(role)
    kwargs: dict[str, Any] = {"temperature": settings.role_temperature(role)}
    if settings.llm_base_url:
        kwargs["base_url"] = settings.llm_base_url
    return init_chat_model(spec, **kwargs)


def complete(model: BaseChatModel, system_prompt: str, user_prompt: str) -> str:
    """Single-turn completion returning the assistant text."""
    response = model.invoke([SystemMessage(system_prompt), HumanMessage(user_prompt)])
    content = response.content
    if isinstance(content, str):
        return content
    # Some providers return a list of content blocks.
    return "".join(
        block.get("text", "") if isinstance(block, dict) else str(block) for block in content
    )
