"""LLM factory for protoPen LangGraph agent.

All models route through the LiteLLM gateway (OpenAI-compatible),
so we use ChatOpenAI for everything.
"""

import os

from langchain_openai import ChatOpenAI

from graph.config import LangGraphConfig


def create_llm(config: LangGraphConfig, model_name: str | None = None) -> ChatOpenAI:
    """Create a LangChain ChatModel from config.

    Routes through the LiteLLM gateway which handles provider
    routing (Anthropic, OpenAI, vLLM, etc.) behind a single
    OpenAI-compatible endpoint.

    ``model_name`` overrides the configured model — used to route auxiliary work
    (e.g. summarization for compaction) to a cheaper/faster gateway alias.
    """
    api_key = config.api_key or os.environ.get("OPENAI_API_KEY", "")

    return ChatOpenAI(
        base_url=config.api_base,
        api_key=api_key,
        model=model_name or config.model_name,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        # Stream tokens. The graph runs model nodes via ``ainvoke``; without this,
        # ``astream_events(v2)`` only emits ``on_chat_model_end`` (the whole
        # message at once), so the console answer lands in one frame at turn end.
        # With streaming on, ``on_chat_model_stream`` fires per token — which
        # server/chat.py turns into ``("text", delta)`` events and a2a_executor
        # forwards as incremental artifact-update frames (live token-by-token).
        streaming=True,
    )
