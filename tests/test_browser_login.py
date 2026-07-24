"""本地登录回调的安全回归测试。"""

import http.client
import logging
import threading
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

from hapsign.login import browser_login


def test_callback_accepts_token_without_logging_it(caplog) -> None:
    callback_data = {}
    callback_event = threading.Event()
    handler = browser_login._make_callback_handler(
        "expected-code", callback_data, callback_event
    )
    server = ThreadingHTTPServer((browser_login._CALLBACK_HOST, 0), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    secret = "sensitive-temp-token"

    try:
        caplog.set_level(logging.DEBUG)
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        body = urlencode({"tempToken": secret, "code": "expected-code"})
        connection.request(
            "POST",
            "/callback",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = connection.getresponse()
        response.read()
        connection.close()

        assert response.status == 302
        assert callback_event.wait(timeout=2)
        assert callback_data["tempToken"] == secret
        assert secret not in caplog.text
    finally:
        server.shutdown()
        server.server_close()


def test_callback_host_is_loopback() -> None:
    assert browser_login._CALLBACK_HOST == "127.0.0.1"


def test_login_opens_system_browser(monkeypatch) -> None:
    callback_event = threading.Event()
    callback_event.set()
    opened = []

    monkeypatch.setattr(
        browser_login.webbrowser,
        "open",
        lambda url, **kwargs: opened.append((url, kwargs)) or True,
    )

    browser_login.BrowserLogin()._browser_login_and_wait(
        "https://example.invalid/login", callback_event
    )

    assert opened[0][0] == "https://example.invalid/login"
