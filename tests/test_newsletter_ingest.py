"""Tests for the shared newsletter ingest helper.

    python -m unittest tests.test_newsletter_ingest
"""

import unittest
from unittest import mock

from webapp import newsletter_ingest


class PublishArticles(unittest.TestCase):
    def setUp(self):
        # These cases cover counting and message shape, not the SSRF guard, and
        # use short unresolvable URLs; treat every URL as a public web address so
        # the guard does not drop them. The guard has its own tests below.
        patcher = mock.patch("webapp.newsletter_ingest.is_safe_public_url", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_counts_published_and_no_subscriber(self):
        articles = [
            {"url": "http://a", "title": "A", "section": "Malware", "priority": "critical"},
            {"url": "http://b", "title": "B"},
        ]
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=[1, 0]) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", articles)
        self.assertEqual(pub.call_count, 2)
        self.assertEqual(counts, {"published": 2, "failed": 0, "no_subscriber": 1})

    def test_skips_articles_without_url(self):
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", return_value=1) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", [{"title": "no url"}])
        pub.assert_not_called()
        self.assertEqual(counts["published"], 0)

    def test_publish_failure_counted(self):
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=OSError("down")):
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", [{"url": "http://a"}])
        self.assertEqual(counts, {"published": 0, "failed": 1, "no_subscriber": 0})

    def test_message_carries_feed_and_section_tags(self):
        captured = {}

        def fake_publish(message):
            captured.update(message)
            return 1

        article = {"url": "http://a", "title": "T", "section": "Vulnerabilities", "priority": "urgent"}
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=fake_publish):
            newsletter_ingest.publish_articles("ETDA CTI Robot", [article])
        self.assertEqual(captured["link"], "http://a")
        self.assertEqual(captured["feed"], "ETDA CTI Robot")
        self.assertIn('zsazsa:newsletter-section="vulnerabilities"', captured["feed_tags"])
        self.assertIn('zsazsa:newsletter-priority="urgent"', captured["feed_tags"])


class PublishArticlesSsrf(unittest.TestCase):
    """The auto IMAP path takes URLs from attacker-controlled newsletter text, so
    only public web addresses reach the scraper; a dropped URL is counted as a
    failure rather than silently, since the counts report delivery."""

    def test_a_non_public_url_is_skipped_and_counted_as_failed(self):
        articles = [
            {"url": "http://169.254.169.254/latest/meta-data/", "title": "metadata"},
            {"url": "https://public.example/advisory", "title": "ok"},
        ]
        safe = lambda u: not u.startswith("http://169.254")  # noqa: E731
        with mock.patch("webapp.newsletter_ingest.is_safe_public_url", side_effect=safe), \
                mock.patch("webapp.newsletter_ingest.scraper_queue.publish", return_value=1) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", articles)
        self.assertEqual(pub.call_count, 1)
        self.assertEqual(pub.call_args.args[0]["link"], "https://public.example/advisory")
        self.assertEqual(counts, {"published": 1, "failed": 1, "no_subscriber": 0})


class ArticlesFromParsed(unittest.TestCase):
    def test_maps_and_drops_urlless(self):
        parsed = {
            "articles": [
                {"primary_url": "http://a", "title": "A", "section": "S", "priority_key": "critical"},
                {"primary_url": "", "title": "no url"},
            ]
        }
        out = newsletter_ingest.articles_from_parsed(parsed)
        self.assertEqual(out, [
            {"url": "http://a", "title": "A", "section": "S", "priority": "critical"},
        ])


if __name__ == "__main__":
    unittest.main()
