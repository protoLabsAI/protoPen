"""KnowledgeBackend protocol conformance (ADR 0031 seam).

Locks the contract: KnowledgeStore must satisfy the KnowledgeBackend protocol
(method names + compatible signatures), so a future alternative backend has a
real, type-checked seam to implement against — and so a rename/removal on the
store is caught here instead of at runtime in the middleware/tools.
"""

from __future__ import annotations

import inspect

from knowledge.backend import KnowledgeBackend
from knowledge.store import KnowledgeStore

_METHODS = ["search", "keyword_search", "hybrid_search", "add_fact", "list_facts", "delete_fact", "get_stats"]


def test_store_is_instance_of_backend(tmp_path):
    store = KnowledgeStore(db_path=tmp_path / "k.db", embed_url="http://127.0.0.1:1")
    # runtime_checkable structural check (method presence).
    assert isinstance(store, KnowledgeBackend)


def test_store_signatures_match_protocol():
    for name in _METHODS:
        proto = getattr(KnowledgeBackend, name)
        impl = getattr(KnowledgeStore, name)
        # Parameter names + defaults the protocol declares must exist on the impl
        # (the impl may add extra optional params, but must accept what callers rely on).
        proto_params = inspect.signature(proto).parameters
        impl_params = inspect.signature(impl).parameters
        for pname, pparam in proto_params.items():
            assert pname in impl_params, f"KnowledgeStore.{name} is missing param {pname!r}"
            if pparam.default is not inspect.Parameter.empty:
                assert impl_params[pname].default == pparam.default, (
                    f"KnowledgeStore.{name}({pname}) default {impl_params[pname].default!r} "
                    f"!= protocol {pparam.default!r}"
                )


def test_protocol_surface_is_the_swappable_subset():
    # The contract intentionally excludes protoPen's security-domain methods —
    # they live on the concrete store, not the swappable backend.
    proto_methods = {n for n in dir(KnowledgeBackend) if not n.startswith("_")}
    assert proto_methods == set(_METHODS)
    for domain_only in ("add_cve", "add_exploit", "add_advisory", "get_topics", "add_digest"):
        assert not hasattr(KnowledgeBackend, domain_only)
        assert hasattr(KnowledgeStore, domain_only)  # still on the concrete store
