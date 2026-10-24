import logging
import time
from datetime import datetime, timezone

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from core.logging_setup import setup_logging
from analyser.products.flash_intel import process as process_flash_intel
from analyser.reader import get_new_scraper_events, load_last_briefing, save_last_briefing, save_last_run
from core.db import init_db, log_event, log_pipeline_run_start, log_pipeline_run_end
from core.misp_client import get_misp, get_misp_webapp
from webapp import analyser_pipeline, feed_cache, job_store, misp_store
from webapp.utils import scraper_enabled


def load_focus_points() -> dict:
    return {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }


def scheduled_actions(now: datetime) -> list[str]:
    """The dashboard's analyser actions this run makes, in the order they go.

    Settings > System switches each one on. The daily briefing comes once a
    day, from its hour on, and last: it rejects the events it finds irrelevant,
    which takes them out of the other two.
    """
    actions = []
    if getattr(config, "ANALYSER_FLASH_INTEL_REQUIREMENTS", False):
        actions.append("flash-intel")
    if getattr(config, "ANALYSER_VULNERABILITY_ADVISORIES", False):
        actions.append("vea")
    if (getattr(config, "ANALYSER_DAILY_BRIEFING", False)
            and now.hour >= getattr(config, "ANALYSER_DAILY_BRIEFING_HOUR", 21)
            and load_last_briefing() != now.date().isoformat()):
        actions.append("daily-briefing")
    return actions


def run_scheduled_actions() -> None:
    logger = logging.getLogger(__name__)
    now = datetime.now(timezone.utc)
    for action in scheduled_actions(now):
        label = analyser_pipeline.ACTION_LABELS[action]
        job = job_store.create_job(action, label=f"Scheduled {label.lower()}",
                                   steps=analyser_pipeline.action_steps(action))
        # Yesterday's events too: one that came in after the last run of the
        # day, or after the day's briefing, would otherwise never be read.
        result = analyser_pipeline.run_action(job["id"], "analyser", triggered_by="schedule", days=2)
        if result is None:
            continue
        logger.info("Scheduled %s: %s", label.lower(), result.get("message", ""))
        if action == "daily-briefing":
            save_last_briefing(now.date().isoformat())


def main() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)
    run_start = int(time.time())
    logger.info("Analyser started")

    init_db()
    run_id = log_pipeline_run_start("analyser", triggered_by="cli")

    try:
        focus_points = load_focus_points()
        # Only the event analysis needs the scraper. An installation that
        # collects from other MISP servers has none, and the run goes ahead with
        # no events so the feed caches below still get their scheduled refresh.
        misp = misp_webapp = None
        events = []
        alerted = set()
        if not scraper_enabled():
            logger.info("No MISP scraper configured; refreshing feed caches only")
        elif getattr(config, "ANALYSER_FLASH_INTEL", True):
            misp = get_misp()
            misp_webapp = get_misp_webapp()
            events = get_new_scraper_events(misp)
            # One alert per event, whichever run made it and whatever became of it.
            alerted = misp_store.flash_intel_source_uuids()
    except Exception as e:
        logger.error("Startup failed: %s", e)
        log_pipeline_run_end(run_id, "failed")
        raise

    counts = {"product_created": 0, "not_relevant": 0, "http_error": 0, "no_content": 0, "error": 0}

    # A run with work registers a job, so the web app can show it while it is
    # going. Scheduled runs that find nothing stay out of the way: they would
    # otherwise keep the job badge lit with nothing to report.
    job = None
    if events:
        job = job_store.create_job("analyser", label="CLI analyser")
        job_store.update_job(job["id"], status="running", message=f"Processing {len(events)} event(s)")

    try:
        for position, event in enumerate(events, start=1):
            job_store.update_job(job["id"], message=f"Event {position} of {len(events)}: {event.info or event.uuid[:8]}")
            if event.uuid in alerted:
                logger.info("Event %s already has a flash intel alert", event.uuid)
                continue
            try:
                result = process_flash_intel(misp, misp_webapp, event, focus_points)
                outcome = result["outcome"]
                counts[outcome] = counts.get(outcome, 0) + 1

                log_event(
                    event_uuid=event.uuid,
                    event_info=event.info,
                    source_feed=result.get("source_feed", "unknown"),
                    outcome=outcome,
                    detail=result.get("detail"),
                )

                # Drafts now require manual review/approval in the webapp. The
                # Mattermost alert is sent from the approval endpoint, not here.

            except Exception as e:
                logger.error("Failed to process event %s: %s", event.uuid, e)
                counts["error"] = counts.get("error", 0) + 1
                log_event(
                    event_uuid=event.uuid,
                    event_info=getattr(event, "info", ""),
                    source_feed="unknown",
                    outcome="error",
                    detail=f"{type(e).__name__}: {e}",
                )

        # Advance the timestamp so events are not reprocessed on the next run,
        # even if some failed. Errored events are visible in the DB log. Never
        # after a run that read no scraper: the watermark is a queue pointer, so
        # moving it over a window nothing was read from skips it for good.
        if misp is not None:
            save_last_run(run_start)

        if scraper_enabled():
            run_scheduled_actions()

        # Cached indicator feeds are re-run here rather than on a timer of their
        # own: this run is already the scheduled MISP work of the application.
        # Missing it only means the next consumer of a stale feed waits for the
        # query, which is what an uncached feed does anyway.
        feeds_refreshed = feed_cache.refresh_due()

        result = {
            "total_events": len(events),
            "product_created": counts.get("product_created", 0),
            "not_relevant": counts.get("not_relevant", 0),
            "http_error": counts.get("http_error", 0),
            "no_content": counts.get("no_content", 0),
            "error": counts.get("error", 0),
            "feed_caches_refreshed": feeds_refreshed,
        }
        log_pipeline_run_end(run_id, "completed", result)
        if job:
            job_store.update_job(
                job["id"], status="completed", result=result,
                message=(f"{len(events)} event(s): {counts.get('product_created', 0)} product(s), "
                         f"{counts.get('not_relevant', 0)} not relevant, {counts.get('error', 0)} error(s)"),
            )
    except Exception as exc:
        # Only this process can close its own run row and job entry. Without
        # this both keep saying "running" long after it is gone, and the web app
        # has no way of telling that from a run that is genuinely still going.
        log_pipeline_run_end(run_id, "failed")
        if job:
            job_store.update_job(job["id"], status="failed", error=str(exc),
                                 message=f"Failed: {exc}")
        raise
    logger.info(
        "Analyser complete: %d events - %d products, %d not relevant, %d HTTP errors, "
        "%d no content, %d errors, %d feed cache(s) refreshed",
        len(events),
        counts.get("product_created", 0),
        counts.get("not_relevant", 0),
        counts.get("http_error", 0),
        counts.get("no_content", 0),
        counts.get("error", 0),
        feeds_refreshed,
    )


if __name__ == "__main__":
    main()
