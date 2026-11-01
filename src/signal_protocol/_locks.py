"""Process-wide locks shared by setup and cipher operations.

Keep a single instance of each lock when the public entry modules are imported
alongside their implementation modules. Reject unsafe same-thread reentry before
acquiring another lock or loading a record that could overwrite in-flight state.
"""

from threading import RLock, local

from signal_protocol.exceptions import ReentrantOperationException

SESSION_LOCK = RLock()
GROUP_LOCK = RLock()
_operation = local()

__all__ = []


class protocol_operation:
    """Reject nested writes in an active domain and enforce session-before-group.

    An RLock alone lets a callback commit a newer record that its caller then
    overwrites. Holding the two distinct locks in opposite orders also deadlocks.
    Session callbacks may install group keys under this fixed lock order. Reads
    under locks already owned by this thread remain safe in either direction.
    """

    def __init__(self, lock, *, read_only=False):
        self.lock = lock
        self.read_only = read_only

    def __enter__(self):
        previous = getattr(_operation, "locks", ())
        nested_write = not self.read_only and self.lock in previous
        reverse_order = (
            self.lock is SESSION_LOCK and GROUP_LOCK in previous and self.lock not in previous
        )
        if nested_write or reverse_order:
            raise ReentrantOperationException(
                "Reentrant protocol operation: defer writes to an active domain and "
                "acquire the session lock before the group lock"
            )
        self.lock.__enter__()
        try:
            self.previous = previous
            _operation.locks = previous + (self.lock,)
        except BaseException:
            self.lock.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if not self.previous:
                del _operation.locks
            else:
                _operation.locks = self.previous
        finally:
            self.lock.__exit__(exc_type, exc_value, traceback)
        # Let Python propagate the original exception without assigning to its
        # traceback (generator context managers do so on newer Python versions).
        return False
