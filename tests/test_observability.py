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


# Runs observability.js under Node with a minimal window and document, then reports what
# the two beforeSend hooks and document.referrer would hand to Vercel.
_HARNESS = r"""
const fs = require("fs");
const [file, page, referrer, ...urls] = process.argv.slice(1);
const doc = { referrer };
global.window = { location: new URL(page) };
global.document = doc;
new Function(fs.readFileSync(file, "utf8"))();
const va = window.vaq.find((c) => c[0] === "beforeSend")[1];
const si = window.siq.find((c) => c[0] === "beforeSend")[1];
const out = { referrer: doc.referrer, va: [], si: [] };
for (const u of urls) {
  const a = va({ type: "pageview", url: u });
  const b = si({ type: "vital", url: u });
  out.va.push(a && a.url);
  out.si.push(b && b.url);
}
out.bad = va({ type: "pageview", url: "http://[" });
console.log(JSON.stringify(out));
"""


def _run_redaction(page: str, referrer: str, *urls: str) -> dict:
    import json
    import shutil
    import subprocess

    from scoped_drive_mcp.dashboard import TEMPLATES_DIR

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    result = subprocess.run(  # noqa: S603 - fixed args: node, this test's harness, test URLs
        [node, "-e", _HARNESS, str(TEMPLATES_DIR / "observability.js"), page, referrer, *urls],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)


def test_redaction_strips_ids_search_text_and_fragments() -> None:
    site = "https://botrbac.example"
    drive_id = "1AbCdEfGhIjKlMnOpQrStUvWxYz"
    out = _run_redaction(
        f"{site}/files",
        f"{site}/files?folder={drive_id}&q=salary+review",
        f"{site}/files?folder={drive_id}&q=salary+review#row",
        f"{site}/requests/{'A' * 32}?tab=people",
        f"{site}/files?tab=allowed",
        f"{site}/files?tab=NotAWord!",
        f"{site}/shared/{drive_id}/x",
    )
    expected = [
        f"{site}/files",
        f"{site}/requests/:id?tab=people",
        f"{site}/files?tab=allowed",
        f"{site}/files",
        f"{site}/shared/:id/x",
    ]
    assert out["va"] == expected
    assert out["si"] == expected
    assert out["referrer"] == f"{site}/files"
    # An address it cannot parse is not sent at all.
    assert out["bad"] is None


def test_redaction_cuts_another_sites_referrer_to_its_origin() -> None:
    out = _run_redaction("https://botrbac.example/", "https://mail.example.com/inbox/123?q=secret")
    assert out["referrer"] == "https://mail.example.com/"
