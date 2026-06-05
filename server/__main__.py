"""Entry point for ``python -m server`` (ADR 0023 package promotion).

``server.py`` became the ``server/`` package; the composition root + CLI entry
(``_main``) live in ``server/__init__.py``. This runs it.
"""

from server import _main

if __name__ == "__main__":
    _main()
