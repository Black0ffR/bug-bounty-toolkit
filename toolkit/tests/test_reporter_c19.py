"""Tests for C19: toolkit/infra/reporter.py shared report generation."""

from toolkit.infra import reporter


def _sample():
    return [
        {
            "id": "a1", "source_tool": "apifuzz.py", "host": "api.x.com",
            "url": "https://api.x.com/v1/users/1", "vuln_class_key": "BOLA_CONFIRMED",
            "severity": "CRITICAL", "title": "BOLA cross-user", "confidence": "confirmed",
            "evidence": "same object returned", "curl_command": "curl ...",
            "remediation": "check ownership", "cvss_vector": "8.8",
        },
        {
            "id": "b2", "source_tool": "ssrfprobe.py", "host": "api.x.com",
            "url": "https://api.x.com/v1/fetch", "vuln_class_key": "SSRF_INTERNAL",
            "severity": "HIGH", "title": "SSRF internal", "confidence": "probable",
            "evidence": "fetched 169.254.169.254", "curl_command": "curl ...",
            "remediation": "allowlist",
        },
        {
            "id": "c3", "source_tool": "jsreaper.py", "host": "x.com",
            "url": "https://x.com/a.js", "vuln_class_key": "SECRET_IN_GIT",
            "severity": "LOW", "title": "Exposed key", "confidence": "candidate",
            "evidence": "aws key found", "curl_command": "",
        },
    ]


def test_hackerone_contains_titles_and_severity():
    out = reporter.generate_hackerone(_sample())
    assert "BOLA cross-user" in out
    assert "SSRF internal" in out
    assert "CRITICAL" in out and "HIGH" in out
    # highest severity first
    assert out.index("BOLA cross-user") < out.index("SSRF internal")
    assert out.index("SSRF internal") < out.index("Exposed key")


def test_bugcrowd_contains_severity_badges():
    out = reporter.generate_bugcrowd(_sample())
    assert "[CRITICAL]" in out
    assert "api.x.com" in out


def test_csv_has_header_and_rows():
    out = reporter.generate_csv(_sample())
    assert out.startswith("id,severity,vuln_class_key")
    assert out.count("\n") == 4  # header + 3 rows (no trailing newline counted)


def test_sarif_structure():
    sarif = reporter.generate_sarif(_sample())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 3
    # one rule per distinct vuln_class_key (3 here)
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 3
    sev_result = next(r for r in sarif["runs"][0]["results"]
                      if r["ruleId"] == "BOLA_CONFIRMED")
    assert sev_result["level"] == "error"  # CRITICAL/HIGH


def test_render_dispatch_and_unknown():
    assert "BOLA" in reporter.render(_sample(), "hackerone")
    sarif = reporter.render(_sample(), "sarif")
    assert sarif["version"] == "2.1.0"
    try:
        reporter.render(_sample(), "nope")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_empty_findings():
    assert "No findings" in reporter.generate_hackerone([])
    assert reporter.generate_csv([]).startswith("id,severity")
    assert reporter.generate_sarif([])["runs"][0]["results"] == []
