"""Tests for P0 crawler: toolkit/infra/spider.py"""

import asyncio

from toolkit.infra import spider


HTML_HOME = """
<html><body>
  <a href="/about">About</a>
  <a href="/login">Login</a>
  <a href="https://evil.example.com/x">external</a>
  <script src="/static/app.js"></script>
</body></html>
"""

HTML_LOGIN = """
<html><body>
  <form action="/login" method="POST">
    <input name="username" value=""/>
    <input name="password" value=""/>
  </form>
  <a href="/home?ref=1&id=5">home</a>
</body></html>
"""


class _FakeClient:
    def __init__(self, pages: dict):
        self.pages = pages

    async def get(self, url, headers=None, timeout=10.0):
        class R:
            pass
        r = R()
        r.text = self.pages.get(url, "")
        r.status_code = 200 if url in self.pages else 404
        return r


def test_extract_links_forms_assets_and_dedup():
    eps = spider.extract_endpoints(HTML_HOME, "http://t.com/")
    by_url = {e.url: e for e in eps}
    assert "http://t.com/about" in by_url
    assert "http://t.com/static/app.js" in by_url
    # extract is scope-agnostic: external link is discovered here; crawl
    # filters it later via same-origin/scope checks.
    assert any("evil.example.com" in e.url for e in eps)


def test_extract_form_records_method_and_params():
    eps = spider.extract_endpoints(HTML_LOGIN, "http://t.com/")
    login = [e for e in eps if e.url.endswith("/login")]
    assert login, "form endpoint missing"
    ep = login[0]
    assert ep.method == "POST"
    assert set(ep.params) == {"username", "password"}
    assert ep.inject_via == "body_form"
    # query-param URL yields params
    home = [e for e in eps if e.url.startswith("http://t.com/home")]
    assert home and set(home[0].params) == {"ref", "id"}


def test_normalize_strips_fragment():
    assert spider._normalize("http://t.com/x?a=1#frag") == "http://t.com/x?a=1"


def test_crawl_discovers_form_on_second_page():
    pages = {
        "http://t.com/": HTML_HOME,
        "http://t.com/login": HTML_LOGIN,
        "http://t.com/about": "<html></html>",
    }
    eps = asyncio.run(spider.crawl("http://t.com/", _FakeClient(pages),
                                   max_depth=2, max_urls=50, concurrency=5))
    urls = {e.url for e in eps}
    assert "http://t.com/login" in urls
    # form params survived the crawl (POST form endpoint, not the GET link)
    login = [e for e in eps if e.url == "http://t.com/login" and e.method == "POST"]
    assert login and set(login[0].params) == {"username", "password"}


def test_crawl_respects_same_origin():
    pages = {
        "http://t.com/": '<a href="http://other.com/z">x</a>',
    }
    eps = asyncio.run(spider.crawl("http://t.com/", _FakeClient(pages),
                                   max_depth=1, max_urls=50))
    assert all("other.com" not in e.url for e in eps)


def test_crawl_injects_seeds_as_endpoints():
    # A hidden endpoint never linked from the home page, supplied as a seed.
    pages = {"http://t.com/": HTML_HOME}
    eps = asyncio.run(spider.crawl(
        "http://t.com/", _FakeClient(pages), max_depth=1, max_urls=50,
        seeds=["http://t.com/hidden?q=1&id=9"],
    ))
    hidden = [e for e in eps if e.url == "http://t.com/hidden?q=1&id=9"]
    assert hidden, "seed endpoint not injected"
    assert set(hidden[0].params) == {"q", "id"}
    assert hidden[0].inject_via == "query"


def test_crawl_seeds_out_of_scope_ignored():
    pages = {"http://t.com/": HTML_HOME}
    eps = asyncio.run(spider.crawl(
        "http://t.com/", _FakeClient(pages), max_depth=1, max_urls=50,
        seeds=["http://evil.example.com/x?a=1"],
    ))
    assert not any("evil.example.com" in e.url for e in eps)
