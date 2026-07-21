"""External secrets-manager integration (port protoAgent ADR 0080).

Pulls secrets from a configured manager (Infisical built-in) into ``os.environ``
before the config parse, so the documented env fallback tier — the gateway key
(``OPENAI_API_KEY``), A2A/operator tokens, and any tool that reads env — sees manager
values on every load path, with rotation-without-restart via an optional refresh.

**Opt-in and additive.** Inert unless a ``secrets_manager`` config section sets
``enabled: true`` — protoPen's existing ``start.sh`` ``infisical export`` boot-snapshot
keeps working untouched until an operator turns this on. See ``hydrate`` for the apply
policy and ``base`` for the provider contract.

Note: this package is ``infra.secrets``; the stdlib ``secrets`` module is unaffected
(absolute imports) — just don't ``from infra import secrets`` in a module that also
wants the stdlib one.
"""

from infra.secrets.base import (
    ENV_NAME_RE,
    ErrorKind,
    FetchResult,
    SecretsProvider,
    SourceConfig,
    get_provider,
    register_secrets_provider,
)
from infra.secrets.hydrate import (
    DISABLE_ENV,
    SecretsRequiredError,
    SourceStatus,
    applied_env_names,
    hydrate_from_docs,
    sensitive_values,
    source_from_docs,
    status,
)
from infra.secrets.infisical import InfisicalProvider

# The built-in provider registers at import — config load resolves providers through
# the registry only, so a fork can replace this with its own registration.
register_secrets_provider(InfisicalProvider())

__all__ = [
    "DISABLE_ENV",
    "ENV_NAME_RE",
    "ErrorKind",
    "FetchResult",
    "InfisicalProvider",
    "SecretsProvider",
    "SecretsRequiredError",
    "SourceConfig",
    "SourceStatus",
    "applied_env_names",
    "get_provider",
    "hydrate_from_docs",
    "register_secrets_provider",
    "sensitive_values",
    "source_from_docs",
    "status",
]
