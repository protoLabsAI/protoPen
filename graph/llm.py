"""LLM factory for protoPen LangGraph agent.

All models route through the LiteLLM gateway (OpenAI-compatible),
so we use ChatOpenAI for everything.
"""

import asyncio
import logging
import os
from collections.abc import AsyncIterator, Callable

import httpcore
import httpx
from langchain_openai import ChatOpenAI

from graph.config import LangGraphConfig

log = logging.getLogger(__name__)

# A provider stream can drop mid-read — an ``httpcore.ReadError`` / ``httpx.TransportError``
# (or a read timeout) surfaces while iterating the SSE body. ``ChatOpenAI(max_retries=…)``
# retries the request *start*, never a mid-body read, so a rate-limited or flaky gateway
# that terminates the response kills the whole turn (port protoAgent #1728). These are the
# read/transport failures we treat as retryable when the stream produced NOTHING yet.
RETRYABLE_STREAM_ERRORS: tuple[type[BaseException], ...] = (
    httpx.TransportError,  # httpx.ReadError / ConnectError / ReadTimeout / …
    httpcore.NetworkError,  # httpcore.ReadError / WriteError / ConnectError (raw, unwrapped)
    httpcore.TimeoutException,  # httpcore.ReadTimeout / ConnectTimeout
)
_STREAM_RETRY_BACKOFF_S = 0.5


async def _stream_with_reconnect(
    make_stream: Callable[[], AsyncIterator],
    *,
    max_retries: int,
    backoff: float = _STREAM_RETRY_BACKOFF_S,
    sleep: Callable = asyncio.sleep,
) -> AsyncIterator:
    """Yield from a model stream, restarting it on a transport/read error that occurs
    **before any item is emitted**.

    Retrying is only safe with zero items emitted: each chunk fires its
    ``on_llm_new_token`` callback as it's yielded, so once one has streamed a fresh
    stream would duplicate it — there we re-raise. This reconnects the model call only;
    it never replays tools or restarts the turn. A provider closing the stream at the
    top (the rate-limit case) emits nothing, so it reconnects cleanly.
    """
    attempts = max(max_retries, 0) + 1
    delay = backoff
    for attempt in range(attempts):
        emitted = 0
        try:
            async for item in make_stream():
                emitted += 1
                yield item
            return
        except RETRYABLE_STREAM_ERRORS as exc:
            if emitted or attempt == attempts - 1:
                raise
            log.warning(
                "model stream dropped before any content (%s: %s) — reconnecting, "
                "attempt %d/%d in %.1fs (provider closed stream; possible rate limit)",
                type(exc).__name__,
                exc,
                attempt + 1,
                attempts - 1,
                delay,
            )
            await sleep(delay)
            delay *= 2


class _ReconnectingChatOpenAI(ChatOpenAI):
    """ChatOpenAI that reconnects a provider stream which drops before emitting any
    content (port protoAgent #1728).

    Transparent pass-through on the happy path; on a mid-read transport error with
    zero chunks yielded it reconnects (within the model's ``max_retries`` budget)
    instead of letting the error kill the turn — the failure mode a rate-limited
    gateway produces. Once a chunk has streamed, the error propagates unchanged."""

    async def _astream(self, *args, **kwargs):
        async for chunk in _stream_with_reconnect(
            lambda: super(_ReconnectingChatOpenAI, self)._astream(*args, **kwargs),
            max_retries=self.max_retries or 0,
        ):
            yield chunk


def create_llm(config: LangGraphConfig, model_name: str | None = None) -> ChatOpenAI:
    """Create a LangChain ChatModel from config.

    Routes through the LiteLLM gateway which handles provider
    routing (Anthropic, OpenAI, vLLM, etc.) behind a single
    OpenAI-compatible endpoint.

    ``model_name`` overrides the configured model — used to route auxiliary work
    (e.g. summarization for compaction) to a cheaper/faster gateway alias.
    """
    api_key = config.api_key or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        # No key yet — a fresh BYO Deck before the setup wizard runs. Construct
        # with a placeholder so the server still BOOTS and can serve the wizard;
        # openai validates the key on use, not construction. Agent turns 401 until
        # the operator completes setup, which rebuilds the graph with the real key.
        api_key = "not-configured"

    return _ReconnectingChatOpenAI(
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
