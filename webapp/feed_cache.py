"""On-disk cache of rendered indicator feeds.

A feed can be given a caching interval. The first request for it runs the query
once, writes the result in every format the feed is served in under
data/feed_cache, and serves those files until the interval has passed. A SOC
polling the feed URL then reads a file instead of sending zsazsa back to MISP
on every pull.

The cache is per feed, not per query: editing a feed drops it, so the next
request runs the new query.

Usage:
    from webapp import feed_cache
    feed_cache.interval(feed)          # "hourly" / "daily" / "weekly", or ""
    feed_cache.read(feed, "json")      # cached body, or None if it must run
    feed_cache.last_copy(feed, "json") # what was written last, however old
    feed_cache.write(feed, bodies)     # {format: body}, for a cached feed
    feed_cache.written_at(feed)        # unix time it was cached, or None
    feed_cache.clear(feed_uuid)        # after an edit or a delete
    feed_cache.failure(feed)           # why the last refresh did not work
    feed_cache.refresh_due()           # from the analyser run
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

from core.atomic_write import write_atomically
from webapp import audit, misp_store

logger = logging.getLogger(__name__)

_CACHE_DIR = Path("data/feed_cache")

# How often a cached feed is refreshed, in the order the form offers them.
INTERVALS = {"hourly": 3600, "daily": 86400, "weekly": 604800}

# A feed refreshes on the clock of the moment it was saved: a feed saved at
# 14:16 refreshes at :16 past the hour, or at 14:16 each day, or on that weekday
# at 14:16. Saving it again moves the schedule to the new time. Feeds saved at
# different moments therefore come due at different moments, instead of every
# feed queueing up on the same round hour.


def interval(feed) -> str:
    """The feed's caching interval, or "" when the feed is not cached."""
    value = (feed.cache_interval or "").strip().lower()
    return value if value in INTERVALS else ""


def anchor(feed):
    """The moment the feed was last saved, which its schedule hangs off.

    Feeds cached before an anchor was stored fall back to when their cache was
    written, and a feed with neither is treated as saved now.
    """
    try:
        return datetime.fromisoformat(feed.cache_anchor or "")
    except ValueError:
        written = written_at(feed)
        return datetime.fromtimestamp(written) if written else datetime.now()


def _slot_at_or_before(moment, feed):
    """The most recent scheduled refresh at or before `moment`."""
    every = interval(feed)
    at = anchor(feed)
    slot = moment.replace(minute=at.minute, second=0, microsecond=0)
    if every == "hourly":
        return slot if slot <= moment else slot - timedelta(hours=1)
    slot = slot.replace(hour=at.hour)
    if every == "daily":
        return slot if slot <= moment else slot - timedelta(days=1)
    slot -= timedelta(days=(slot.weekday() - at.weekday()) % 7)
    return slot if slot <= moment else slot - timedelta(days=7)


def next_refresh(feed):
    """When the feed is next due, or None when it is not cached."""
    if not interval(feed):
        return None
    now = datetime.now()
    return _slot_at_or_before(now, feed) + timedelta(seconds=INTERVALS[interval(feed)])


def schedule_text(feed) -> str:
    """The schedule in words, e.g. "every hour at :16"."""
    every = interval(feed)
    if not every:
        return ""
    at = anchor(feed)
    if every == "hourly":
        return f"every hour at :{at:%M}"
    if every == "daily":
        return f"every day at {at:%H:%M}"
    return f"every {at:%A} at {at:%H:%M}"


# A refresh that failed leaves this beside the cached formats, so the feed list
# can say that what it serves is older than it should be.
_FAILURE_SUFFIX = "error"

# The analyser has no signed-in analyst to file its work under.
_SCHEDULED_BY = "analyser"

# A MISP error can carry a whole response body; the note and the log entry only
# need enough of it to tell one failure from another.
_MAX_REASON = 300


def _safe_suffix(suffix):
    """A cache file suffix that is safe to use on disk, or None when unknown."""
    value = (suffix or "").strip().lower()
    if value == _FAILURE_SUFFIX:
        return value
    if value in misp_store.INDICATOR_FORMATS:
        return value
    return None


def _path(feed_uuid, suffix):
    """One cached file of one feed.

    Ids reach this module from URLs, clear() straight from a delete request, so
    the name is taken without any directory part: a feed id is a file in here,
    never a path out of here.
    """
    safe_suffix = _safe_suffix(suffix)
    if safe_suffix is None:
        raise ValueError("Unknown cache file suffix")
    return _CACHE_DIR / Path(f"{feed_uuid}.{safe_suffix}").name


def _files(feed_uuid):
    """The cached files of one feed. A list, because clear() deletes as it goes."""
    if not _CACHE_DIR.is_dir():
        return []
    return sorted(_CACHE_DIR.glob(Path(f"{feed_uuid}.*").name))


def _rendered_files(feed_uuid):
    """The cached formats, without the note a failed refresh leaves beside them."""
    return [p for p in _files(feed_uuid) if p.suffix != f".{_FAILURE_SUFFIX}"]


def note_failure(feed, reason) -> None:
    """Remember that a refresh did not work, and why."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        write_atomically(_path(feed.uuid, _FAILURE_SUFFIX),
                         json.dumps({"at": datetime.now().isoformat(timespec="seconds"),
                                     "reason": str(reason)[:_MAX_REASON]}))
    except OSError as exc:
        logger.warning("Could not note the failed refresh of feed %s: %s", feed.feed_id, exc)


def clear_failure(feed) -> None:
    """Forget an earlier failure: this refresh worked."""
    try:
        _path(feed.uuid, _FAILURE_SUFFIX).unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Could not clear the failure note of feed %s: %s", feed.feed_id, exc)


def failure(feed):
    """The last refresh that did not work, as {"at": datetime, "reason": str}.

    None when the last one worked, which is also what a note zsazsa can no
    longer read comes down to.
    """
    try:
        note = json.loads(_path(feed.uuid, _FAILURE_SUFFIX).read_text())
        return {"at": datetime.fromisoformat(note["at"]), "reason": note.get("reason", "")}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def read(feed, fmt):
    """The cached body for one format, or None when the query has to run.

    None covers every reason not to use the cache: the feed is not cached,
    nothing has been written yet, and the schedule has come round again.
    """
    if not interval(feed):
        return None
    safe_fmt = _safe_suffix(fmt)
    if safe_fmt is None:
        return None
    path = _path(feed.uuid, safe_fmt)
    try:
        if path.stat().st_mtime < _slot_at_or_before(datetime.now(), feed).timestamp():
            return None
    except OSError:
        return None
    return _read(path)


def last_copy(feed, fmt):
    """What was written last, however long ago, or None if nothing ever was.

    For the one case where age is the lesser problem: the feed is due, the query
    behind it cannot be run, and the choice is between last week's indicators
    and none at all. A consumer that is handed nothing takes it for an answer.
    """
    if not interval(feed):
        return None
    safe_fmt = _safe_suffix(fmt)
    if safe_fmt is None:
        return None
    return _read(_path(feed.uuid, safe_fmt))


def _read(path):
    try:
        # newline="" so the CRLF the CSV writer produces survives the round trip
        # and a cached pull is byte for byte what a live one returns.
        with open(path, encoding="utf-8", newline="") as f:
            return f.read()
    except OSError:
        return None


def write(feed, bodies: dict) -> None:
    """Write every rendered format of a cached feed.

    One call writes one query's result, so the formats agree with each other.
    A failure halfway would leave the rest holding an older query, which nothing
    downstream can tell apart, so the whole set is dropped and the next request
    runs the query again.
    """
    if not interval(feed):
        return
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        for fmt, body in bodies.items():
            write_atomically(_path(feed.uuid, fmt), body)
    except OSError as exc:
        # Serving the feed matters more than caching it.
        logger.warning("Could not cache feed %s: %s", feed.feed_id, exc)
        # Clear first: it takes the note with it, and the note is about this.
        clear(feed.uuid)
        note_failure(feed, exc)


def written_at(feed):
    """When the feed was last cached, as a unix timestamp, or None."""
    times = [p.stat().st_mtime for p in _rendered_files(feed.uuid)]
    return max(times) if times else None


def clear(feed_uuid: str) -> None:
    """Drop the cached files after the feed changed or was deleted."""
    for path in _files(feed_uuid):
        try:
            path.unlink()
        except OSError as exc:
            logger.warning("Could not drop cached feed file %s: %s", path, exc)


def render_all(rows, feed) -> dict:
    """Every format of one result, so a single query fills the whole cache."""
    return {fmt: misp_store.indicator_export(rows, fmt, feed) for fmt in misp_store.INDICATOR_FORMATS}


def _is_due(feed) -> bool:
    """True when the feed has not been refreshed since its last scheduled slot."""
    if not interval(feed):
        return False
    written = written_at(feed)
    return written is None or written < _slot_at_or_before(datetime.now(), feed).timestamp()


def refresh_due() -> int:
    """Re-run every cached feed whose interval has passed. Returns how many.

    Called from the analyser run, which is where the scheduled MISP work of the
    application happens. A feed that fails is left alone, so the previous copy
    keeps being served rather than being replaced by an empty one.
    """
    try:
        feeds = misp_store.list_indicator_feeds()
    except Exception as exc:
        logger.warning("Could not list the feeds to refresh: %s", exc)
        return 0
    _drop_orphans(feeds)
    refreshed = 0
    for feed in feeds:
        if not _is_due(feed):
            continue
        query = feed.query or {}
        try:
            rows = misp_store.search_indicators(query, server_ids=query.get("servers"))
            write(feed, render_all(rows, feed))
        except Exception as exc:
            logger.warning("Could not refresh the cache of feed %s: %s", feed.feed_id, exc)
            note_failure(feed, exc)
            _log_refresh(feed, "refresh-failed", str(exc))
            continue
        clear_failure(feed)
        logger.info("Cached feed %s refreshed: %s indicators", feed.feed_id, len(rows))
        _log_refresh(feed, "refresh", f"{len(rows)} indicators")
        refreshed += 1
    return refreshed


def _drop_orphans(feeds) -> None:
    """Remove cached files of feeds that no longer exist.

    Deleting a feed in zsazsa clears its files; one deleted straight in MISP, or
    one whose delete was interrupted, leaves them behind for good.
    """
    known = {feed.uuid for feed in feeds}
    dropped = set()
    for path in _files("*"):
        if path.stem in known:
            continue
        try:
            path.unlink()
            dropped.add(path.stem)
        except OSError as exc:
            logger.warning("Could not drop the orphaned cache file %s: %s", path, exc)
    if dropped:
        logger.info("Dropped the cache of %d feed(s) that no longer exist: %s",
                    len(dropped), ", ".join(sorted(dropped)))


def _log_refresh(feed, action, details) -> None:
    """Put the refresh in the audit log, where the analyst reads it.

    Wrapped because this is a note about the work, not the work itself: the
    analyser must not stop refreshing feeds over a log that cannot be written.
    """
    try:
        audit.record(action, "indicator-feed", entity_id=feed.uuid,
                     entity_label=feed.feed_id, details=details[:_MAX_REASON],
                     user=_SCHEDULED_BY)
    except Exception as exc:
        logger.warning("Could not log the refresh of feed %s: %s", feed.feed_id, exc)
