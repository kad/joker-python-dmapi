# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

import json
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
    monkeypatch.setenv("JOKER_BACKUP_DIR", "")  # never write backups outside tmp_path in tests


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


def test_official_and_alias_names_match(
    api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]
) -> None:
    api.get(f"{BASE}/dns-zone-get", body=reply("@ A 0 1.2.3.4 300"))
    assert main(["dns-zone-get", "example.com"]) == 0
    assert main(["get-zone", "example.com"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["@ A 0 1.2.3.4 300", "@ A 0 1.2.3.4 300"]


def test_dns_zone_put_alias_and_backup(
    api: responses.RequestsMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bk = tmp_path / "bk"
    monkeypatch.setenv("JOKER_BACKUP_DIR", str(bk))
    api.get(f"{BASE}/dns-zone-get", body=reply("@ A 0 1.2.3.4 300"))
    api.post(f"{BASE}/dns-zone-put", body=reply())
    zone = tmp_path / "z"
    zone.write_text("@ A 0 5.6.7.8 300\n")
    assert main(["put-zone", "example.com", str(zone)]) == 0
    (saved,) = bk.glob("example.com-*.zone")
    assert saved.read_text().strip() == "@ A 0 1.2.3.4 300"


def test_no_backup_flag(api: responses.RequestsMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JOKER_BACKUP_DIR", str(tmp_path / "bk"))
    api.post(f"{BASE}/dns-zone-put", body=reply())
    zone = tmp_path / "z"
    zone.write_text("@ A 0 5.6.7.8 300\n")
    assert main(["--no-backup", "dns-zone-put", "example.com", str(zone)]) == 0
    assert not (tmp_path / "bk").exists()


def test_backup_failure_exit_code(
    api: responses.RequestsMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    blocker = tmp_path / "f"
    blocker.write_text("x")
    monkeypatch.setenv("JOKER_BACKUP_DIR", str(blocker / "sub"))
    api.get(f"{BASE}/dns-zone-get", body=reply("@ A 0 1.2.3.4 300"))
    zone = tmp_path / "z"
    zone.write_text("@ A 0 5.6.7.8 300\n")
    assert main(["dns-zone-put", "example.com", str(zone)]) == 1
    assert "backup" in capsys.readouterr().err
    assert all(not url(c).endswith("dns-zone-put") for c in api.calls)


def test_query_balance_json(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    api.get(
        f"{BASE}/query-account-balance",
        body=reply("1.00\t2.00\t3.00\tEUR", code=1000, Columns="available,pending,total,currency"),
    )
    assert main(["--json", "query-account-balance"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "available": "1.00",
        "pending": "2.00",
        "total": "3.00",
        "currency": "EUR",
    }


def test_query_domain_list_table(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    api.get(f"{BASE}/query-domain-list", body=reply("a.com 2030-01-01"))
    assert main(["query-domain-list"]) == 0
    assert capsys.readouterr().out.splitlines() == ["domain\texpires", "a.com\t2030-01-01"]


def test_query_order_list_options(api: responses.RequestsMock) -> None:
    api.get(f"{BASE}/query-order-list", body=reply("", Columns="order_id"))
    assert main(["query-order-list", "--type", "renew", "--show-all"]) == 0
    sent = next(url(c) for c in api.calls if "query-order-list" in url(c))
    assert "type=renew" in sent
    assert "show-all=1" in sent


@pytest.mark.parametrize(
    "argv",
    [
        ["--json", "query-profile"],
        ["query-profile", "--json"],
        ["--json", "query-profile", "--json"],
    ],
)
def test_global_options_anywhere(
    api: responses.RequestsMock, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    api.get(f"{BASE}/query-profile", body=reply("name: Joe"))
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out) == {"name": "Joe"}


def test_option_before_command_survives_subparser_default(
    api: responses.RequestsMock, tmp_path: Path
) -> None:
    zone = tmp_path / "z"
    zone.write_text("@ A 0 5.6.7.8 300\n")
    api.post(f"{BASE}/dns-zone-put", body=reply())
    assert main(["--no-backup", "dns-zone-put", "example.com", str(zone)]) == 0
    assert main(["dns-zone-put", "example.com", str(zone), "--no-backup"]) == 0


def test_domain_get_property_all(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    api.get(f"{BASE}/domain-get-property", body=reply("autorenew: 1"))
    assert main(["domain-get-property", "x.com"]) == 0
    assert "autorenew: 1" in capsys.readouterr().out


def test_put_zone_unreadable_file(
    api: responses.RequestsMock, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    zone = tmp_path / "z"
    zone.write_bytes(b"\xff\xfe\x00bad")
    assert main(["dns-zone-put", "example.com", str(zone)]) == 1
    assert "can't read" in capsys.readouterr().err


def test_dns_zone_get_json(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    api.get(f"{BASE}/dns-zone-get", body=reply("@ A 0 1.2.3.4 300"))
    assert main(["--json", "dns-zone-get", "example.com"]) == 0
    assert json.loads(capsys.readouterr().out) == {"domain": "example.com", "zone": "@ A 0 1.2.3.4 300"}


def test_info_json(api: responses.RequestsMock, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["account"] == {"User-Login": "me"}
    assert data["zones"] == [{"name": "example.com", "expires": "2030-01-01"}]
