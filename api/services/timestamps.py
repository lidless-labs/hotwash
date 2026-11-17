"""Playbook write timestamps.

SQLite's ``CURRENT_TIMESTAMP`` (``func.now()``) has one-second resolution, which
is too coarse for the optimistic-concurrency precondition on
``PUT /api/playbooks/{id}``: an edit in the same second as a read would leave
``updated_at`` unchanged and the precondition would not see it.

Writes therefore set ``updated_at`` in Python to a naive-UTC microsecond
timestamp that is strictly greater than the stored value. The DateTime columns
are naive, so aware client-supplied values are normalized to naive UTC before
they are compared.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional


def utcnow() -> datetime:
    """Naive UTC now, matching the naive DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_naive_utc(value: datetime) -> datetime:
    """Normalize a timestamp so aware and naive values compare equal."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def next_updated_at(stored: Optional[datetime]) -> datetime:
    """A microsecond timestamp strictly greater than the stored value.

    ``now`` is normally enough. It is not when the clock did not advance (two
    writes inside one microsecond, or a stored value from the future), so fall
    back to ``stored + 1 microsecond`` to keep every accepted write observable.
    """
    now = utcnow()
    if stored is None:
        return now
    stored_naive = as_naive_utc(stored)
    if now <= stored_naive:
        return stored_naive + timedelta(microseconds=1)
    return now


def sqlite_timestamp_text(value: datetime) -> str:
    """The text SQLAlchemy's SQLite DATETIME bind processor writes for a value.

    Used for the conditional UPDATE's equality check, where the column is
    compared as text (see ``playbooks.update_playbook``).
    """
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")
