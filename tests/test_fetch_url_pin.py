"""The /api/fetch-url SSRF guard pins the connection to the validated address.

is_safe_public_url / resolve_public_url resolve the host once; without pinning,
curl_cffi resolves it again and a name answering public then internal (DNS
rebinding, CWE-367) would be fetched. These tests mock the resolver and the HTTP
client so they run offline, and assert the fetch is pinned to exactly the
address that was validated. One runs real curl against a server on this host,
under a name DNS does not know, to show curl uses the pin rather than a lookup.

    python -m unittest tests.test_fetch_url_pin
"""

import http.server
import threading
import unittest
from unittest import mock

from curl_cffi import CurlOpt
from flask import Flask

from webapp.routes import api

_HTML = "<html><head><title>t</title></head><body>hello</body></html>"


def _addrinfo(ip):
    return [(2, 1, 6, "", (ip, 80))]


class FetchUrlPin(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(api.bp)
        self.client = app.test_client()

    def _post(self, url):
        return self.client.post("/api/fetch-url", json={"url": url})

    def test_a_named_host_is_pinned_to_its_validated_address(self):
        with mock.patch("socket.getaddrinfo", return_value=_addrinfo("8.8.8.8")), \
                mock.patch("curl_cffi.requests.Session") as Session:
            Session.return_value.__enter__.return_value.get.return_value.text = _HTML
            resp = self._post("http://fakehost.example/")
        self.assertEqual(resp.status_code, 200)
        Session.assert_called_once_with(
            curl_options={CurlOpt.RESOLVE: ["fakehost.example:80:8.8.8.8"]})

    def test_an_ip_literal_host_is_not_pinned(self):
        with mock.patch("socket.getaddrinfo", return_value=_addrinfo("8.8.8.8")), \
                mock.patch("curl_cffi.requests.Session") as Session:
            Session.return_value.__enter__.return_value.get.return_value.text = _HTML
            resp = self._post("http://8.8.8.8/")
        self.assertEqual(resp.status_code, 200)
        Session.assert_called_once_with(curl_options={})

    def test_a_host_resolving_internal_is_refused_and_never_fetched(self):
        with mock.patch("socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")), \
                mock.patch("curl_cffi.requests.Session") as Session:
            with self.assertLogs(api.logger, "WARNING"):
                resp = self._post("http://rebind.example/")
        self.assertEqual(resp.status_code, 400)
        Session.assert_not_called()

    def test_curl_connects_to_the_validated_address_without_a_second_lookup(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _Page)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        # As if the name had answered 127.0.0.1 when it was validated. DNS has
        # no answer for .invalid at all, so a page coming back means curl used
        # the validated address rather than looking the name up.
        validated = ("rebind.invalid", port, ["127.0.0.1"])
        with mock.patch.object(api, "resolve_public_url", return_value=validated):
            answer = self._post(f"http://rebind.invalid:{port}/").get_json()
        self.assertIsNone(answer["error"])
        self.assertEqual(answer["title"], "Pinned")
        self.assertIn(f"rebind.invalid:{port}", answer["content"], "the Host header names the URL's host")


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"<html><head><title>Pinned</title></head><body>{self.headers['Host']}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    unittest.main()
