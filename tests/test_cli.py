# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

from pathlib import Path

import pytest
import responses

from joker_dmapi.cli import main

from .conftest import BASE, LOGIN_OK, reply, url


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JOKER_API_KEY", "k")
    monkeypatch.delenv("JOKER_USERNAME", raising=False)
    monkeypatch.delenv("JOKER_PASSWORD", raising=False)


@pytest.fixture
def api(mocked: responses.RequestsMock) -> responses.RequestsMock:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/logout", body=reply())
    mocked.get(f"{BASE}/dns-zone-list", body=reply("example.com 2030-01-01"))
    return mocked


def test_missing_credentials(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("JOKER_API_KEY")
    assert main(["info"]) == 1
    assert "JOKER_API_KEY" in capsys.readouterr().err


def test_present_unknown_zone_fails(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["present", "_acme-challenge.other.org.", "v"]) == 1
    assert "no zone" in capsys.readouterr().err
    assert url(api.calls[-1]).startswith(f"{BASE}/logout")  # still logs out


def test_present_adds_record(api: responses.RequestsMock) -> None:
    api.get(f"{BASE}/dns-zone-get", body=reply("@ A 0 1.2.3.4 300"))
    api.post(f"{BASE}/dns-zone-put", body=reply())
    assert main(["present", "--", "_acme-challenge.example.com.", "tok"]) == 0
    body = next(c.request.body for c in api.calls if url(c).endswith("dns-zone-put"))
    assert isinstance(body, str)
    assert "_acme-challenge+TXT+0" in body


def test_cleanup_passes_value(api: responses.RequestsMock) -> None:
    api.get(
        f"{BASE}/dns-zone-get",
        body=reply('@ A 0 1.2.3.4 300\n_acme-challenge TXT 0 "a" 60\n_acme-challenge TXT 0 "b" 60'),
    )
    api.post(f"{BASE}/dns-zone-put", body=reply())
    assert main(["cleanup", "_acme-challenge.example.com.", "a"]) == 0
    body = next(c.request.body for c in api.calls if url(c).endswith("dns-zone-put"))
    assert isinstance(body, str)
    assert "%22b%22" in body
    assert "%22a%22" not in body


def test_api_error_exit_code(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    api.get(f"{BASE}/dns-zone-get", body=reply(code=2, text="no such zone"))
    assert main(["get-zone", "x.com"]) == 1
    assert "no such zone" in capsys.readouterr().err


def test_put_zone_missing_file(api: responses.RequestsMock, tmp_path: Path) -> None:
    assert main(["put-zone", "example.com", str(tmp_path / "nope")]) == 1


def test_put_zone_unreadable_file(
    api: responses.RequestsMock, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    zone = tmp_path / "z"
    zone.write_bytes(b"\xff\xfe\x00bad")
    assert main(["put-zone", "example.com", str(zone)]) == 1
    assert "can't read" in capsys.readouterr().err
