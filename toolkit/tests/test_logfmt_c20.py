"""Tests for C20: toolkit/infra/logfmt.py JSON log formatter."""

import json
import logging

from toolkit.infra import logfmt


def test_json_formatter_emits_single_object():
    fmt = logfmt.JsonFormatter()
    rec = logging.LogRecord(
        name="apifuzz", level=logging.INFO, pathname=__file__, lineno=1,
        msg="probe %s", args=("https://x.com",), exc_info=None,
    )
    line = fmt.format(rec)
    obj = json.loads(line)  # must be valid single-line JSON
    assert obj["level"] == "INFO"
    assert obj["logger"] == "apifuzz"
    assert obj["msg"] == "probe https://x.com"
    assert "ts" in obj


def test_configure_logging_json_swaps_formatter_and_is_idempotent():
    logfmt.configure_logging(fmt="json", level=logging.DEBUG)
    root = logging.getLogger()
    jsons = [h for h in root.handlers if getattr(h, "_toolfmt", False) or
             isinstance(h.formatter, logfmt.JsonFormatter)]
    assert any(isinstance(h.formatter, logfmt.JsonFormatter) for h in root.handlers)
    # idempotent: reconfigure does not duplicate toolkit handlers
    n_before = len([h for h in root.handlers if getattr(h, "_toolkit_logfmt", False)])
    logfmt.configure_logging(fmt="json", level=logging.DEBUG)
    n_after = len([h for h in root.handlers if getattr(h, "_toolkit_logfmt", False)])
    assert n_after == n_before
    # restore text for other tests
    logfmt.configure_logging(fmt="text", level=logging.INFO)


def test_configure_logging_text_uses_bracket_formatter():
    logfmt.configure_logging(fmt="text", level=logging.INFO)
    assert any(
        isinstance(h.formatter, logging.Formatter)
        and not isinstance(h.formatter, logfmt.JsonFormatter)
        for h in logging.getLogger().handlers
        if getattr(h, "_toolkit_logfmt", False)
    )
