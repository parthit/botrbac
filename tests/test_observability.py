"""Vercel Speed Insights / Web Analytics tags, and the page-stability markup in base.html."""

import pytest

from tests.dash import client

SCRIPTS = (
    '<script src="/observability.js" defer></script>',
    '<script src="/_vercel/speed-insights/script.js" defer></script>',
    '<script src="/_vercel/insights/script.js" defer></script>',
)


@pytest.fixture
def c(p2_app):
    return client(p2_app)


def test_no_vercel_scripts_off_vercel(c, monkeypatch) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    page = c.get("/login").text
    assert "/_vercel/" not in page and "/observability.js" not in page


def test_vercel_scripts_on_vercel_with_redaction_first(c, monkeypatch) -> None:
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("VERCEL_OBSERVABILITY", raising=False)
    for path in ("/login", "/privacy", "/terms"):
        page = c.get(path).text
        at = [page.index(tag) for tag in SCRIPTS]
        # observability.js must run first: it installs beforeSend before either script sends.
        assert at == sorted(at), path


@pytest.mark.parametrize("value", ["off", "0", "false", "No"])
def test_vercel_scripts_can_be_turned_off(c, monkeypatch, value) -> None:
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_OBSERVABILITY", value)
    assert "/_vercel/" not in c.get("/login").text


def test_observability_script_is_served_and_strips_ids(c) -> None:
    r = c.get("/observability.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/javascript")
    assert r.headers["cache-control"] == "no-cache" and r.headers["etag"]
    body = r.text
    assert 'window.va("beforeSend", beforeSend)' in body
    assert 'window.si("beforeSend", beforeSend)' in body
    assert 'url.hash = ""' in body and ":id" in body


def test_privacy_policy_names_the_measurement(c) -> None:
    page = c.get("/privacy").text
    assert "Vercel Speed Insights and Web Analytics" in page
    assert "use no cookies" in page


def test_fonts_are_preloaded_with_a_matched_fallback(c) -> None:
    page = c.get("/login").text
    for weight in (400, 500, 600):
        assert (
            f'<link rel="preload" href="/fonts/geist-{weight}.woff2" as="font" '
            'type="font/woff2" crossorigin>' in page
        )
    css = c.get("/app.css").text
    assert '--font: Geist, "Geist Fallback"' in css
    assert css.count('font-family: "Geist Fallback"') == 3
    assert "@view-transition { navigation: auto; }" in css
