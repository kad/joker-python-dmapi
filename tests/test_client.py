# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

from pathlib import Path

import pytest
import responses

from joker_dmapi import (
    Joker,
    JokerAPIError,
    JokerAuthError,
    JokerBackupError,
    JokerConnectionError,
    split_fqdn,
)

from .conftest import BASE, LOGIN_OK, reply, url

ZONE = (
    '@ A 0 1.2.3.4 300\n\nwww A 0 1.2.3.5 300\n_acme-challenge TXT 0 "one" 60\n_acme-challenge TXT 0 "two" 60'
)


def test_requires_credentials() -> None:
    with pytest.raises(ValueError, match="api_key"):
        Joker()


@pytest.mark.parametrize(
    ("fqdn", "expected"),
    [
        ("_acme-challenge.example.com.", ("example.com", "_acme-challenge")),
        ("example.com.", ("example.com", "@")),
        ("a.b.example.com", ("example.com", "a.b")),
        ("a.sub.example.com.", ("sub.example.com", "a")),
        ("foo.notexample.com.", None),
        ("other.org.", None),
    ],
)
def test_split_fqdn(fqdn: str, expected: tuple[str, str] | None) -> None:
    assert split_fqdn(fqdn, ["example.com", "sub.example.com"]) == expected


def test_login_uses_post_and_stores_session(mocked: responses.RequestsMock) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    j = Joker(api_key="secret")
    j.login()
    assert j.auth_sid == "sid123"
    assert j.account_info == {"User-Login": "me"}
    assert j.supported_domains == ["example.com"]
    assert mocked.calls[0].request.body == "api-key=secret"
    assert "secret" not in url(mocked.calls[0])


def test_login_failure(mocked: responses.RequestsMock) -> None:
    mocked.post(f"{BASE}/login", body=reply(code=4, text="Access denied"))
    with pytest.raises(JokerAuthError) as ei:
        Joker(api_key="k").login()
    assert ei.value.code == 4


def test_http_error_is_connection_error(mocked: responses.RequestsMock) -> None:
    mocked.post(f"{BASE}/login", status=500)
    with pytest.raises(JokerConnectionError):
        Joker(api_key="k").login()


def test_context_manager_logs_out(mocked: responses.RequestsMock) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/logout", body=reply())
    with Joker(api_key="k") as j:
        assert j.auth_sid
    assert j.auth_sid == ""
    assert "auth-sid=sid123" in url(mocked.calls[1])


def test_logout_code_1000_is_success(
    mocked: responses.RequestsMock, caplog: pytest.LogCaptureFixture
) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/logout", body=reply(code=1000))
    with Joker(api_key="k"):
        pass
    assert "logout failed" not in caplog.text


def test_logout_failure_does_not_mask_error(mocked: responses.RequestsMock) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/logout", body=reply(code=1, text="boom"))
    with pytest.raises(RuntimeError, match="original"), Joker(api_key="k"):
        raise RuntimeError("original")


def test_auth_sid_is_not_shared_between_clients(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-list", body=reply())
    other = Joker(api_key="k")
    other.request("dns-zone-list")
    assert "auth-sid" not in url(mocked.calls[-1])


def test_dns_zone_list(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-list", body=reply("a.com 2030-01-01\nb.com 2031-01-01", Separator="SPACE"))
    assert [z.name for z in client.dns_zone_list()] == ["a.com", "b.com"]


def test_api_error_raised(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply(code=2, text="no such zone"))
    with pytest.raises(JokerAPIError):
        client.dns_zone_get("nope.com")


def test_add_txt_keeps_whole_zone(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    mocked.post(f"{BASE}/dns-zone-put", body=reply())
    client.add_txt_record("example.com", "_acme-challenge", "three")
    sent = mocked.calls[-1].request.body
    assert isinstance(sent, str)
    assert "www+A+0+1.2.3.5+300" in sent  # record after the blank line survives
    assert "three" in sent


@pytest.mark.parametrize(
    ("record", "value"), [("r", 'a"b'), ("r", "a\nb"), ("r", "a\\b"), ("a b", "v"), ("r\n", "v")]
)
def test_add_txt_rejects_unsafe_input(client: Joker, record: str, value: str) -> None:
    with pytest.raises(ValueError, match="unsupported"):
        client.add_txt_record("example.com", record, value)


def test_remove_txt_only_matching_value(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    mocked.post(f"{BASE}/dns-zone-put", body=reply())
    assert client.remove_txt_record("example.com", "_acme-challenge", "one")
    sent = mocked.calls[-1].request.body
    assert isinstance(sent, str)
    assert "two" in sent
    assert "%22one%22" not in sent


def test_remove_txt_without_value_removes_all(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    mocked.post(f"{BASE}/dns-zone-put", body=reply())
    client.remove_txt_record("example.com", "_acme-challenge")
    sent = mocked.calls[-1].request.body
    assert isinstance(sent, str)
    assert "_acme-challenge" not in sent


def test_remove_txt_no_match_skips_put(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    assert not client.remove_txt_record("example.com", "_acme-challenge", "absent")
    assert all(not url(c).endswith("dns-zone-put") for c in mocked.calls)


def test_remove_txt_tolerates_trailing_space_in_value(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply('@ A 0 1.2.3.4 300\n_a TXT 0 "v " 60'))
    mocked.post(f"{BASE}/dns-zone-put", body=reply())
    assert client.remove_txt_record("example.com", "_a", "v")


def _backup_client(tmp_path: Path) -> Joker:
    return Joker(api_key="k", backup_dir=tmp_path / "bk")


def test_put_saves_backup_first(mocked: responses.RequestsMock, tmp_path: Path) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    mocked.post(f"{BASE}/dns-zone-put", body=reply())
    j = _backup_client(tmp_path)
    j.login()
    j.dns_zone_put("example.com", "@ A 0 9.9.9.9 300")
    (saved,) = (tmp_path / "bk").glob("example.com-*.zone")
    assert saved.read_text().strip() == ZONE.strip()
    assert saved.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "bk").stat().st_mode & 0o777 == 0o700
    # the backup was taken before the write
    assert [url(c).split("?")[0].rsplit("/", 1)[1] for c in mocked.calls][-2:] == [
        "dns-zone-get",
        "dns-zone-put",
    ]


def test_txt_edit_backs_up_without_extra_fetch(mocked: responses.RequestsMock, tmp_path: Path) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    mocked.post(f"{BASE}/dns-zone-put", body=reply())
    j = _backup_client(tmp_path)
    j.login()
    j.add_txt_record("example.com", "_acme-challenge", "three")
    assert sum(url(c).split("?")[0].endswith("dns-zone-get") for c in mocked.calls) == 1
    assert len(list((tmp_path / "bk").glob("*.zone"))) == 1


def test_backup_failure_blocks_write(mocked: responses.RequestsMock, tmp_path: Path) -> None:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    blocker = tmp_path / "file"
    blocker.write_text("x")
    j = Joker(api_key="k", backup_dir=blocker / "sub")
    j.login()
    with pytest.raises(JokerBackupError):
        j.dns_zone_put("example.com", "@ A 0 9.9.9.9 300")
    assert all(not url(c).endswith("dns-zone-put") for c in mocked.calls)


def test_backup_filename_is_sanitized(mocked: responses.RequestsMock, tmp_path: Path) -> None:
    j = _backup_client(tmp_path)
    path = j.backup_zone("../evil/x", "z")
    assert path.parent == tmp_path / "bk"


def test_include_defaults(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply(ZONE))
    client.dns_zone_get("example.com", include_defaults=True)
    assert "include-defaults=1" in url(mocked.calls[-1])


def test_redirect_is_an_error(mocked: responses.RequestsMock) -> None:
    mocked.post(f"{BASE}/login", status=302, headers={"Location": "https://evil.example/"})
    with pytest.raises(JokerConnectionError, match="302"):
        Joker(api_key="k").login()
    assert len(mocked.calls) == 1  # the redirect target was not requested


def test_debug_log_shows_reply_but_not_login(
    client: Joker, mocked: responses.RequestsMock, caplog: pytest.LogCaptureFixture
) -> None:
    mocked.get(f"{BASE}/dns-zone-get", body=reply("@ A 0 1.2.3.4 300"))
    with caplog.at_level("DEBUG", logger="joker_dmapi"):
        client.dns_zone_get("example.com")
        mocked.post(f"{BASE}/login", body=LOGIN_OK)
        client.login()
    assert "@ A 0 1.2.3.4 300" in caplog.text
    assert "sid123" not in caplog.text
