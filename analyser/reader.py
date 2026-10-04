import json
import logging
import time
from pathlib import Path

import config
from core.atomic_write import write_atomically

logger = logging.getLogger(__name__)


def _load_state() -> dict:
    path = Path(config.STATE_FILE)
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("State file unreadable, starting fresh")
        return {}


def _save_state(state: dict) -> None:
    path = Path(config.STATE_FILE)
    path.parent.mkdir(exist_ok=True)
    # The analyser and the web app each keep their own key in here, from
    # separate processes, so a half-written file loses one of them.
    write_atomically(path, json.dumps(state))


def load_last_run() -> int | None:
    return _load_state().get("analyser_last_run")


def save_last_run(timestamp: int) -> None:
    """Advance the analyser's watermark. Only the analyser run may call this.

    get_new_scraper_events() asks MISP for events changed since this timestamp,
    so it is a queue pointer, not a clock: anything published before it and not
    yet processed is skipped for good. Something that merely wants to say "the
    pipeline ran just now" wants save_last_action().
    """
    state = _load_state()
    state["analyser_last_run"] = timestamp
    _save_state(state)


def load_last_action() -> int | None:
    return _load_state().get("pipeline_last_action")


def save_last_action(timestamp: int) -> None:
    """Record that a dashboard analyser action finished, for display only.

    The dashboard actions read today's incomplete events themselves and cover a
    different set than the analyser run does, so this is kept apart from the
    watermark above.
    """
    state = _load_state()
    state["pipeline_last_action"] = timestamp
    _save_state(state)


def get_new_scraper_events(misp) -> list:
    last_run = load_last_run()
    lookback = int(time.time()) - (config.POLL_WINDOW_HOURS * 3600)
    since = max(last_run, lookback) if last_run else lookback

    # MISP REST treats multi-tag filters as OR. Search by the marker only,
    # then keep events that also carry workflow:state="incomplete".
    #
    # Every page, not just the first: the run moves the watermark past
    # everything changed before it started, so an event left on page two is
    # never asked for again. Events already complete still carry the marker
    # and fill pages too.
    limit = getattr(config, "MISP_SCRAPER_LIMIT", 500)
    events, page = [], 1
    while True:
        batch = misp.search(
            tags=[config.SCRAPER_MARKER_TAG],
            timestamp=since,
            limit=limit,
            page=page,
            pythonify=True,
        )
        if isinstance(batch, dict) and "errors" in batch:
            # Raised rather than read as "nothing new": an empty result lets
            # the run advance the watermark over a window it never read.
            raise RuntimeError(f"MISP search failed: {batch['errors']}")
        batch = batch or []
        events.extend(batch)
        if not limit or len(batch) < limit:
            break
        page += 1

    needed = 'workflow:state="incomplete"'
    filtered = [
        e for e in (events or [])
        if any(getattr(t, "name", "") == needed for t in (getattr(e, "tags", []) or []))
    ]

    logger.info("Found %d scraper events to process", len(filtered))
    return filtered
