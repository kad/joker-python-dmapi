# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

from decimal import Decimal
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from joker_dmapi import AccountBalance, Joker, JokerAPIError

from .conftest import BASE, reply, url


def test_query_profile(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/query-profile", body=reply("name: Joe\nbalance: 1.50"))
    assert client.query_profile() == {"name": "Joe", "balance": "1.50"}


def test_query_account_balance(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(
        f"{BASE}/query-account-balance",
        body=reply(
            "975.00\t25.00\t1000.00\tUSD",
            code=1000,
            Columns="available,pending,total,currency",
            Separator="TAB",
        ),
    )
    assert client.query_account_balance() == AccountBalance(
        Decimal("975.00"), Decimal("25.00"), Decimal("1000.00"), "USD"
    )


def test_query_order_list_filters(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(
        f"{BASE}/query-order-list",
        body=reply("1\t2\tok\trenew\texample.com", Columns="order_id,proc_id,status,type,identifier"),
    )
    rows = client.query_order_list(fqdn_like="*.com", show_all=True, status=None, asc=False)
    assert rows == [
        {"order_id": "1", "proc_id": "2", "status": "ok", "type": "renew", "identifier": "example.com"}
    ]
    sent = url(mocked.calls[-1])
    assert "fqdn-like=" in sent
    assert "show-all=1" in sent
    assert "status=" not in sent
    assert "asc=" not in sent


def test_query_domain_list_columns(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/query-domain-list", body=reply("a.com 2030-01-01 lock,autorenew"))
    rows = client.query_domain_list("a*", show_status=True)
    assert rows == [{"domain": "a.com", "expires": "2030-01-01", "status": "lock,autorenew"}]
    assert "showstatus=1" in url(mocked.calls[-1])


def test_query_ns_list_full(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/query-ns-list", body=reply("ns.example.com\t1.2.3.4\t-"))
    assert client.query_ns_list(full=True) == [{"host": "ns.example.com", "ipv4": "1.2.3.4", "ipv6": "-"}]


def test_query_contact_list(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/query-contact-list", body=reply("CCOM-1"))
    assert client.query_contact_list(tld="com") == [{"handle": "CCOM-1"}]
    assert "tld=com" in url(mocked.calls[-1])


def test_domain_check(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(
        f"{BASE}/domain-check",
        body=reply("domain-status: available\ndomain-price-create: 8.21 USD 1y", code=1000),
    )
    result = client.domain_check("x.com", check_price="create")
    assert result["domain-status"] == "available"
    assert result["domain-price-create"] == "8.21 USD 1y"
    assert "Status-Code" not in result


def test_domain_get_property(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/domain-get-property", body=reply("autorenew: 0"))
    assert client.domain_get_property("x.com", "autorenew") == "0"


def test_grants_list_and_results(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/grants-list", body=reply("grant 1 s domain x.com @admin me you 5 a@b.c nick"))
    assert client.grants_list("x.com")[0][:2] == ["grant", "1"]
    mocked.get(f"{BASE}/result-list", body=reply("20240101000000 sv 99 domain-renew ack -"))
    assert client.result_list(pending=True)[0][2] == "99"
    assert "pending=1" in url(mocked.calls[-1])


def test_result_retrieve_needs_id(client: Joker) -> None:
    with pytest.raises(ValueError, match="proc_id or svtrid"):
        client.result_retrieve()


def test_domain_get_properties_skips_unsupported(client: Joker, mocked: responses.RequestsMock) -> None:
    def cb(request: object) -> tuple[int, dict[str, str], str]:
        name = parse_qs(urlparse(request.url).query)["pname"][0]  # type: ignore[attr-defined]
        if name == "whois-opt-out":
            return 200, {}, reply(code=2000, text="not supported")
        return 200, {}, reply(f"{name}: 1")

    mocked.add_callback(responses.GET, f"{BASE}/domain-get-property", callback=cb)
    assert client.domain_get_properties("x.com") == {
        "autorenew": "1",
        "privacy": "1",
        "gdpr-opt-in": "1",
    }


def test_result_retrieve_sends_only_svtrid_when_both_given(
    client: Joker, mocked: responses.RequestsMock
) -> None:
    mocked.get(f"{BASE}/result-retrieve", body=reply("done"))
    client.result_retrieve(proc_id="1", svtrid="2")
    sent = url(mocked.calls[-1])
    assert "svtrid=2" in sent
    assert "proc-id" not in sent
    client.result_retrieve(proc_id="1")
    assert "proc-id=1" in url(mocked.calls[-1])


def test_domain_get_properties_first_error_is_raised(client: Joker, mocked: responses.RequestsMock) -> None:
    mocked.get(f"{BASE}/domain-get-property", body=reply(code=2000, text="no such domain"))
    with pytest.raises(JokerAPIError):
        client.domain_get_properties("nope.com")
