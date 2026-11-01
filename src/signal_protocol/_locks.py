"""Process-wide locks shared by setup and cipher operations.

Keep a single instance of each lock when the public entry modules are imported
alongside their implementation modules. Reject unsafe same-thread reentry before
acquiring another lock or loading a record that could overwrite in-flight state.
"""

from contextlib import contextmanager
from threading import RLock, local

from signal_protocol.exceptions import ReentrantOperationException

SESSION_LOCK = RLock()
GROUP_LOCK = RLock()
_operation = local()

__all__ = []


@contextmanager
def protocol_operation(lock, *, read_only=False):
    """Reject nested writes in an active domain and enforce session-before-group.

    An RLock alone lets a callback commit a newer record that its caller then
    overwrites. Holding the two distinct locks in opposite orders also deadlocks.
    Session callbacks may install group keys under this fixed lock order. Reads
    under locks already owned by this thread remain safe in either direction.
    """
    previous = getattr(_operation, "locks", ())
    nested_write = not read_only and lock in previous
    reverse_order = lock is SESSION_LOCK and GROUP_LOCK in previous and lock not in previous
    if nested_write or reverse_order:
        raise ReentrantOperationException(
            "Reentrant protocol operation: defer writes to an active domain and "
            "acquire the session lock before the group lock"
        )
    with lock:
        _operation.locks = previous + (lock,)
        try:
            yield
        finally:
            if not previous:
                del _operation.locks
            else:
                _operation.locks = previous
