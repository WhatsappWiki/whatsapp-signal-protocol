"""Process-wide locks shared by setup and cipher operations.

Keep a single instance of each lock when the public entry modules are imported
alongside their implementation modules. Store transaction semantics are unchanged.
"""

from threading import RLock

SESSION_LOCK = RLock()
GROUP_LOCK = RLock()

__all__ = []
