# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

from collections.abc import Iterator

import pytest
import responses

from joker_dmapi import Joker

BASE = "https://dmapi.joker.com/request"
LOGIN_OK = "Status-Code: 0\nStatus-Text: OK\nAuth-Sid: sid123\nUser-Login: me\n\nexample.com\n"


def url(call: responses.Call) -> str:
    return call.request.url or ""


def reply(body: str = "", code: int = 0, text: str = "OK", **headers: str) -> str:
    head = "".join(f"{k}: {v}\n" for k, v in {"Status-Code": code, "Status-Text": text, **headers}.items())
    return f"{head}\n{body}"


@pytest.fixture
def mocked() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture
def client(mocked: responses.RequestsMock) -> Joker:
    mocked.post(f"{BASE}/login", body=LOGIN_OK)
    mocked.get(f"{BASE}/logout", body=reply())
    j = Joker(api_key="k")
    j.login()
    return j
