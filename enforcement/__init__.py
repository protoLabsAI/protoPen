"""Enforcement & safety layer for protoPen.

Hard enforcement of engagement scope, kill chain phases, and rate limits
at the middleware layer. All checks happen before tool execution — not via
prompt instructions.
"""
