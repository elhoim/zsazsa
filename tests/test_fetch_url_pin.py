"""The /api/fetch-url SSRF guard pins the connection to the validated address.

is_safe_public_url / resolve_public_url resolve the host once; without pinning,
curl_cffi resolves it again and a name answering public then internal (DNS
rebinding, CWE-367) would be fetched. These tests mock the resolver and the HTTP
client so they run offline, and assert the fetch is pinned to exactly the
address that was validated.

    python -m unittest tests.test_fetch_url_pin
"""

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
            Session.return_value.get.return_value.text = _HTML
            resp = self._post("http://fakehost.example/")
        self.assertEqual(resp.status_code, 200)
        Session.assert_called_once_with(
            curl_options={CurlOpt.RESOLVE: ["fakehost.example:80:8.8.8.8"]})

    def test_an_ip_literal_host_is_not_pinned(self):
        with mock.patch("socket.getaddrinfo", return_value=_addrinfo("8.8.8.8")), \
                mock.patch("curl_cffi.requests.Session") as Session:
            Session.return_value.get.return_value.text = _HTML
            resp = self._post("http://8.8.8.8/")
        self.assertEqual(resp.status_code, 200)
        Session.assert_called_once_with()

    def test_a_host_resolving_internal_is_refused_and_never_fetched(self):
        with mock.patch("socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")), \
                mock.patch("curl_cffi.requests.Session") as Session:
            resp = self._post("http://rebind.example/")
        self.assertEqual(resp.status_code, 400)
        Session.assert_not_called()


if __name__ == "__main__":
    unittest.main()
