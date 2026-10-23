# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

from joker_dmapi import JokerResponse


def test_headers_and_status() -> None:
    r = JokerResponse.parse("Status-Code: 0\nStatus-Text: OK\n\nbody")
    assert r.status == (0, "OK")
    assert r.ok
    assert r.body == "body"


def test_body_keeps_blank_lines() -> None:
    r = JokerResponse.parse("Status-Code: 0\n\n@ A 1.2.3.4\n\nwww A 1.2.3.5\n")
    assert r.body == "@ A 1.2.3.4\n\nwww A 1.2.3.5"


def test_crlf() -> None:
    r = JokerResponse.parse("Status-Code: 2\r\nStatus-Text: bad\r\n\r\nx")
    assert r.status == (2, "bad")
    assert r.body == "x"


def test_missing_status() -> None:
    r = JokerResponse.parse("Foo: bar\n\n")
    assert r.status == (-1, "")
    assert not r.ok


def test_rows_tab_and_dicts() -> None:
    r = JokerResponse.parse(
        "Separator: TAB\nColumns: domain,expiration\n\na.com\t2030-01-01\nb.com\t2031-01-01"
    )
    assert r.as_rows()[1] == ["b.com", "2031-01-01"]
    assert r.as_dicts()[0] == {"domain": "a.com", "expiration": "2030-01-01"}


def test_dicts_without_columns() -> None:
    assert JokerResponse.parse("Status-Code: 0\n\na b").as_dicts() == []


def test_ok_codes() -> None:
    def ok(code: int) -> bool:
        return JokerResponse.parse(f"Status-Code: {code}\n\n").ok

    assert ok(0)
    assert ok(1000)
    assert ok(1999)
    assert not ok(2000)
    assert not ok(1)
    assert not ok(-1)
