"""Integration tests for protoPen's A2A 1.0 port.

Locks the agent card that ``server._build_agent_card_proto`` produces (an
``a2a-sdk`` proto ``AgentCard`` built via ``protolabs_a2a.build_agent_card``),
serialized to the 1.0 wire JSON the SDK serves at
``/.well-known/agent-card.json``:

- capabilities advertise streaming + pushNotifications (so SDK clients switch
  to the async/streaming path);
- the JSONRPC ``supportedInterfaces`` entry points at /a2a, protocol 1.0
  (regression guard — a misplaced url makes clients POST to / and 405);
- provider is the fleet provider block;
- auth advertises apiKey only (protoPen authenticates via X-API-Key; bearer is
  never advertised);
- protoPen declares ONLY the tool-call-v1 extension — it emits tool-call
  DataParts but not cost / confidence / worldstate-delta, so the others must
  NOT be declared (don't promise DataParts the runtime never produces).
"""

from __future__ import annotations

from google.protobuf.json_format import MessageToDict

# A representative protoPen card dict (mirrors the shape of server.AGENT_CARD).
_SAMPLE_CARD = {
    "name": "protopen",
    "description": "Autonomous pen testing and security intelligence agent.",
    "url": "http://steamdeck:7870/a2a",
    "version": "2.0",
    "skills": [
        {
            "id": "passive_recon",
            "name": "Passive Reconnaissance",
            "description": "Passive recon on a target scope.",
            "tags": ["wifi", "rf", "recon", "passive"],
            "examples": ["Scan all WiFi networks in the 2.4 and 5 GHz bands"],
        },
    ],
}


def _card_json() -> dict:
    from server import _build_agent_card_proto

    card = _build_agent_card_proto(_SAMPLE_CARD)
    return MessageToDict(card, preserving_proto_field_name=False)


def test_agent_card_advertises_async_capabilities() -> None:
    caps = _card_json()["capabilities"]
    assert caps["streaming"] is True
    assert caps["pushNotifications"] is True


def test_agent_card_jsonrpc_interface_points_at_rpc_endpoint() -> None:
    """The JSONRPC interface url must target the /a2a path (protocol 1.0)."""
    card = _card_json()
    ifaces = card["supportedInterfaces"]
    jsonrpc = next(i for i in ifaces if i["protocolBinding"] == "JSONRPC")
    assert jsonrpc["url"].endswith("/a2a")
    assert jsonrpc["protocolVersion"] == "1.0"


def test_agent_card_provider_is_fleet_provider() -> None:
    provider = _card_json()["provider"]
    assert provider["organization"] == "protoLabs AI"
    assert provider["url"] == "https://protolabs.ai"


def test_agent_card_has_at_least_one_skill() -> None:
    skills = _card_json().get("skills", [])
    assert skills, "agent card must declare at least one skill"
    for skill in skills:
        assert "id" in skill
        assert "name" in skill
        assert "description" in skill


def test_agent_card_advertises_apikey_only() -> None:
    """protoPen authenticates via X-API-Key; bearer is never advertised."""
    card = _card_json()
    schemes = card.get("securitySchemes", {})
    assert "apiKey" in schemes, "apiKey scheme must always be present"
    assert "bearer" not in schemes, "protoPen must not advertise the bearer scheme"
    reqs = card.get("securityRequirements", [])
    scheme_keys = [set(r.get("schemes", {}).keys()) for r in reqs]
    assert scheme_keys == [{"apiKey"}]


def test_agent_card_declares_only_tool_call_extension() -> None:
    """protoPen emits tool-call DataParts but not cost / confidence /
    worldstate-delta — so only tool-call-v1 may be declared. Declaring an
    extension the runtime never emits would mislead consumers into waiting for
    DataParts that never arrive."""
    import protolabs_a2a as pa

    exts = _card_json()["capabilities"].get("extensions", [])
    declared = {e.get("uri") for e in exts}
    assert declared == {pa.TOOL_CALL_EXT_URI}
    assert pa.COST_EXT_URI not in declared
    assert pa.CONFIDENCE_EXT_URI not in declared
    assert pa.WORLDSTATE_DELTA_EXT_URI not in declared
