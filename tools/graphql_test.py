"""GraphQL testing tool — introspection, schema extraction, query fuzzing."""
from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
""".strip()

_FIELD_SUGGESTION_QUERY = '{ __type(name: "{type_name}") { name fields { name type { name kind } } } }'


class GraphqlTestTool(BasePentestTool):
    """Wrapper for GraphQL security testing."""

    name = "graphql_test"
    description = (
        "GraphQL security testing — introspection, schema extraction, "
        "query depth/complexity fuzzing, batch query abuse, field suggestions."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "gql_introspect": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "r=requests.post('{url}',json={{'query':'''{introspection_query}'''}},"
                "headers={headers},timeout=10); "
                "data=r.json(); "
                "types=[t for t in data.get('data',{{}}).get('__schema',{{}}).get('types',[]) "
                "if not t['name'].startswith('__')]; "
                "print(json.dumps({{'status':r.status_code,'introspection_enabled':True,"
                "'type_count':len(types),'types':[{{'name':t['name'],'kind':t['kind'],"
                "'field_count':len(t.get('fields',[]) or [])}} for t in types[:50]]}}))",
            ],
            "timeout": 30,
            "description": "Test if GraphQL introspection is enabled and extract schema",
        },
        "gql_depth_test": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "def nested(field,depth):\n"
                "  if depth<=0: return field\n"
                "  return field+' {{ '+nested(field,depth-1)+' }}'\n"
                "results=[]; "
                "for d in range(1,{max_depth}+1):\n"
                "  q='{{ '+nested('{field}',d)+' }}'\n"
                "  try:\n"
                "    r=requests.post('{url}',json={{'query':q}},headers={headers},timeout=5)\n"
                "    results.append({{'depth':d,'status':r.status_code,'has_errors':'errors' in r.json()}})\n"
                "  except: results.append({{'depth':d,'status':'timeout','has_errors':True}}); break\n"
                "max_allowed=max((r['depth'] for r in results if not r.get('has_errors')),default=0); "
                "print(json.dumps({{'max_depth_tested':{max_depth},'max_depth_allowed':max_allowed,"
                "'no_depth_limit':max_allowed>={max_depth},'results':results}}))",
            ],
            "timeout": 60,
            "description": "Test query depth limits",
        },
        "gql_batch": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "batch=[{{'query':'{query}'}} for _ in range({batch_size})]; "
                "r=requests.post('{url}',json=batch,headers={headers},timeout=10); "
                "print(json.dumps({{'batch_size':{batch_size},'status':r.status_code,"
                "'batch_accepted':isinstance(r.json(),list),"
                "'response_count':len(r.json()) if isinstance(r.json(),list) else 1}}))",
            ],
            "timeout": 30,
            "description": "Test batch query support (potential DoS vector)",
        },
        "gql_field_suggest": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "typos=['pasword','emial','usrname','adres','phne','tken','secrt','admn']; "
                "results=[]; "
                "for t in typos:\n"
                "  r=requests.post('{url}',json={{'query':'{{ '+t+' }}'}},headers={headers},timeout=5)\n"
                "  body=r.json()\n"
                "  errors=body.get('errors',[])\n"
                "  suggestions=[]\n"
                "  for e in errors:\n"
                "    msg=e.get('message','')\n"
                "    if 'Did you mean' in msg: suggestions.append(msg)\n"
                "  if suggestions: results.append({{'typo':t,'suggestions':suggestions}})\n"
                "print(json.dumps({{'field_suggestions':results,"
                "'note':'Suggestions reveal valid field names'}}))",
            ],
            "timeout": 30,
            "description": "Extract field names via suggestion mechanism",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "",
        headers: str = "{}",
        query: str = "{ __typename }",
        field: str = "__typename",
        type_name: str = "Query",
        max_depth: int = 20,
        batch_size: int = 10,
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                url=url, headers=headers, query=query, field=field,
                type_name=type_name, max_depth=max_depth,
                batch_size=batch_size,
                introspection_query=_INTROSPECTION_QUERY.replace("'", "\\'"),
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 60))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url,
        )
