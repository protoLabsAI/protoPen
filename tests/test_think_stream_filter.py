"""Tests for the stateful streamed <think>...</think> filter (server/chat._ThinkStreamFilter).

Covers the failure modes of the old per-chunk _strip_think: hidden reasoning leaking when a tag
straddles a chunk boundary, and inter-token spaces being stripped.
"""

from server.chat import _ThinkStreamFilter


def _run(chunks):
    f = _ThinkStreamFilter()
    return "".join(f.feed(c) for c in chunks) + f.flush()


def test_preserves_inter_token_spaces():
    # streamed tokens carry a leading space; the filter must not eat them
    assert _run(["the", " quick", " brown", " fox"]) == "the quick brown fox"


def test_think_block_within_one_chunk_removed():
    assert _run(["hi <think>secret</think> there"]) == "hi  there"


def test_think_spanning_chunk_boundaries_does_not_leak():
    # <think>, the reasoning, and </think> arrive in separate chunks — 'secret' must never surface
    assert _run(["hello <thi", "nk>sec", "ret</thi", "nk> world"]) == "hello  world"


def test_tag_split_one_char_per_chunk():
    assert _run(list("A<think>X</think>B")) == "AB"


def test_stray_close_tag_dropped():
    assert _run(["done</think> ok"]) == "done ok"


def test_unterminated_think_at_stream_end_is_suppressed():
    # a think block that never closes must not leak its content on flush
    assert _run(["visible <think>never closes"]) == "visible "


def test_multiple_think_blocks():
    assert _run(["a <think>x</think> b <think>y</think> c"]) == "a  b  c"
