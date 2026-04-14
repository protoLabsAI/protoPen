#!/usr/bin/env python3
"""SAML response decoder and analyzer.

Base64-decodes (and optionally inflates) a SAML response, parses XML,
and checks for security issues like missing signatures, weak NameID types,
and missing InResponseTo attributes.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import logging
import zlib
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# XML namespaces commonly used in SAML
SAML_NS = {
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'xenc': 'http://www.w3.org/2001/04/xmlenc#',
}

NAMEID_FORMAT_LABELS = {
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress': 'emailAddress',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient': 'transient',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent': 'persistent',
    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified': 'unspecified',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:entity': 'entity',
}


def _decode_saml_response(b64_str: str) -> bytes:
    """Decode base64, try inflate if deflated."""
    # Clean up URL encoding artifacts
    b64_clean = b64_str.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=').strip()

    # Add padding
    pad = 4 - len(b64_clean) % 4
    if pad != 4:
        b64_clean += '=' * pad

    raw = base64.b64decode(b64_clean)

    # Try to inflate (deflate-encoded SAML redirect bindings)
    try:
        inflated = zlib.decompress(raw, -zlib.MAX_WBITS)
        return inflated
    except Exception:
        pass

    # Try gzip
    try:
        import gzip
        return gzip.decompress(raw)
    except Exception:
        pass

    return raw


def analyze_saml_xml(xml_bytes: bytes) -> list[dict[str, Any]]:
    """Parse SAML XML and check for security issues."""
    findings: list[dict[str, Any]] = []

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        findings.append({
            "severity": "error",
            "vulnerability_type": "saml_xml_parse_error",
            "message": f"Could not parse SAML XML: {exc}",
        })
        return findings

    tag = root.tag.lower()
    if 'response' not in tag and 'assertion' not in tag:
        findings.append({
            "severity": "info",
            "vulnerability_type": "saml_decoded",
            "message": f"Decoded SAML element: {root.tag}",
        })

    # Check for Signature element
    sig_elem = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    is_signed = sig_elem is not None

    # Check for InResponseTo attribute
    in_response_to = root.get('InResponseTo')
    has_in_response_to = bool(in_response_to)

    # Check for Conditions element (replay prevention)
    conditions = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
    has_conditions = conditions is not None
    not_before = conditions.get('NotBefore') if conditions is not None else None
    not_on_or_after = conditions.get('NotOnOrAfter') if conditions is not None else None

    # Get NameID
    nameid_elem = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
    if nameid_elem is None:
        nameid_elem = root.find('.//{urn:oasis:names:tc:SAML:1.1:assertion}NameID')
    nameid_value = nameid_elem.text if nameid_elem is not None else None
    nameid_format = NAMEID_FORMAT_LABELS.get(
        (nameid_elem.get('Format') if nameid_elem is not None else '') or '',
        (nameid_elem.get('Format') if nameid_elem is not None else 'unspecified') or 'unspecified',
    )

    # Get Subject element
    subject_confirmation = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData')
    recipient = subject_confirmation.get('Recipient') if subject_confirmation is not None else None

    # Get attribute statements
    attributes: dict[str, str] = {}
    for attr in root.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        attr_name = attr.get('Name', 'unknown')
        vals = [v.text for v in attr.findall('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue') if v.text]
        attributes[attr_name] = ', '.join(vals)

    # Summary finding
    summary_parts = [
        f"NameID: {nameid_format}",
        f"Signed: {'yes' if is_signed else 'NO'}",
        f"InResponseTo: {'yes' if has_in_response_to else 'missing'}",
    ]
    if nameid_value:
        # Mask PII
        masked = nameid_value[:3] + "..." if len(nameid_value) > 3 else "***"
        summary_parts.append(f"NameID value: {masked}")
    if attributes:
        summary_parts.append(f"Attributes: {', '.join(list(attributes.keys())[:5])}")

    findings.append({
        "severity": "info",
        "vulnerability_type": "saml_decoded",
        "message": ", ".join(summary_parts),
    })

    # Security issue findings
    if not is_signed:
        findings.append({
            "severity": "critical",
            "vulnerability_type": "saml_unsigned",
            "message": "SAML response has no XML Signature — authentication bypass possible via forged assertions",
        })

    if not has_in_response_to:
        findings.append({
            "severity": "medium",
            "vulnerability_type": "saml_missing_inresponseto",
            "message": "SAML response missing InResponseTo attribute — unsolicited response may be accepted (CSRF-like attack)",
        })

    if not has_conditions:
        findings.append({
            "severity": "medium",
            "vulnerability_type": "saml_missing_conditions",
            "message": "SAML assertion has no Conditions element — no NotBefore/NotOnOrAfter time bounds",
        })

    if nameid_format == 'unspecified':
        findings.append({
            "severity": "low",
            "vulnerability_type": "saml_unspecified_nameid_format",
            "message": "NameID format is 'unspecified' — may allow NameID injection depending on SP implementation",
        })

    # Check audience restriction
    audience = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Audience')
    if audience is None:
        findings.append({
            "severity": "medium",
            "vulnerability_type": "saml_missing_audience",
            "message": "SAML assertion has no AudienceRestriction — assertion may be accepted by any SP",
        })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="SAML response decoder and analyzer")
    parser.add_argument("--response", required=True, help="Base64-encoded SAML response string")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        xml_bytes = _decode_saml_response(args.response)
        findings = analyze_saml_xml(xml_bytes)
        result["findings"] = findings

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "decode_error",
            "message": f"Failed to decode SAML response: {exc}",
        })
        logger.error("saml_decode error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
