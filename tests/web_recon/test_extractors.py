from vrp_hunt.web_recon import (
    extract_endpoint_paths,
    extract_javascript_urls,
    extract_parameter_names,
    extract_secret_notes,
)


def test_extract_javascript_urls_resolves_relative_sources() -> None:
    urls = extract_javascript_urls('<script src="/static/app.js"></script>', "https://www.google.com/")
    assert urls == ["https://www.google.com/static/app.js"]


def test_extract_endpoint_paths() -> None:
    assert "/api/v1/profile" in extract_endpoint_paths('fetch("/api/v1/profile")')


def test_extract_parameter_names() -> None:
    assert extract_parameter_names("https://www.google.com/search?q=x", '"/next?page="') == ["page", "q"]


def test_extract_secret_notes_redacts_values() -> None:
    notes = extract_secret_notes("const apiKey = 'AIza12345678901234567890';", parent="https://x/")
    assert notes
    assert notes[0].kind == "note"
    assert notes[0].metadata["redacted"] == "true"
    assert "AIza" not in notes[0].value
