"""Parser for GraphQL testing output."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_graphql(raw: str, store: "TargetStore") -> list[dict]:
    """Parse GraphQL testing output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        if data.get("introspection_enabled"):
            entities.append({
                "type": "graphql_finding",
                "finding": "introspection_enabled",
                "type_count": data.get("type_count", 0),
            })
        if data.get("no_depth_limit"):
            entities.append({
                "type": "graphql_finding",
                "finding": "no_depth_limit",
                "max_depth_allowed": data.get("max_depth_allowed", 0),
            })
        if data.get("batch_accepted"):
            entities.append({
                "type": "graphql_finding",
                "finding": "batch_queries_accepted",
                "batch_size": data.get("batch_size", 0),
            })
        for suggestion in data.get("field_suggestions", []):
            entities.append({
                "type": "graphql_field",
                "typo": suggestion.get("typo", ""),
                "suggestions": suggestion.get("suggestions", []),
            })
    except json.JSONDecodeError:
        pass
    return entities


PARSER_MAP[("graphql_test", "gql_introspect")] = parse_graphql
PARSER_MAP[("graphql_test", "gql_depth_test")] = parse_graphql
PARSER_MAP[("graphql_test", "gql_batch")] = parse_graphql
PARSER_MAP[("graphql_test", "gql_field_suggest")] = parse_graphql
