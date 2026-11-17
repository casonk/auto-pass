from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "auto_pass" / "web" / "templates"


def test_web_pages_load_shared_portfolio_chrome():
    for name in ("base.html", "login.html"):
        template = (TEMPLATES / name).read_text(encoding="utf-8")
        assert '{% include "_portfolio_theme.html" %}' in template
        assert 'data-bs-theme="dark"' not in template

    theme = (TEMPLATES / "_portfolio_theme.html").read_text(encoding="utf-8")
    assert 'href="/_portfolio/theme.css"' in theme
    assert 'src="/_portfolio/theme.js"' in theme
    assert 'src="/_portfolio/chrome.js"' in theme
    assert "--bs-body-bg: var(--bg)" in theme
    assert "--bs-card-bg: var(--surface)" in theme
    assert "--bs-btn-bg: var(--accent)" in theme
