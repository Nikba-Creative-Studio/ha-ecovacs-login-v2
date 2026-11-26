# SPDX-License-Identifier: GPL-3.0-or-later
"""Helpers adapted from DeebotUniverse/client.py tests at tag 18.7.0.

Source: https://github.com/DeebotUniverse/client.py/blob/4ffed4097bf1169bdc8d9d5c051fd77cbe4d856c/tests/test_authentication.py
The upstream project authors retain copyright in the adapted helpers.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import orjson
from aiohttp import hdrs, web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

_PUBLIC_KEY_CONFIG = "PUBLIC.KEY.CONFIG"


@dataclass(frozen=True, kw_only=True)
class _RecordedRequest:
    """Request received by the fake Ecovacs api."""

    path: str
    query: dict[str, str]
    json: dict[str, Any] | None


class _FakeEcovacsApi:
    """Fake Ecovacs api, which answers with the configured payload per endpoint.

    Requests are routed by the last segment of their path, so a test only needs
    to configure the endpoints it cares about. Requesting an endpoint without a
    payload fails with a 404 instead of silently succeeding.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self.url = ""
        self.responses = responses
        self.requests: defaultdict[str, list[_RecordedRequest]] = defaultdict(list)
        self._server: TestServer | None = None

    async def start(self) -> None:
        """Start the api."""
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self._handle)
        self._server = TestServer(app)
        # the access log would leak the credentials of the query into the log
        await self._server.start_server(access_log=None)
        self.url = str(self._server.make_url("")).rstrip("/")

    async def stop(self) -> None:
        """Stop the api."""
        if self._server is not None:
            await self._server.close()

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        endpoint = request.path.rpartition("/")[2]
        self.requests[endpoint].append(
            _RecordedRequest(
                path=request.path,
                query=dict(request.query),
                json=orjson.loads(await request.read())
                if request.can_read_body
                else None,
            )
        )

        if endpoint not in self.responses:
            raise web.HTTPNotFound
        body = orjson.dumps(self.responses[endpoint])

        if request.method == hdrs.METH_POST:
            return web.Response(body=body, content_type="application/json")
        # the auth api returns a json, but declares it as text
        return web.Response(body=body, content_type="text/plain", charset="utf-8")


def _key_config(value: Any) -> dict[str, Any]:
    return {"key": _PUBLIC_KEY_CONFIG, "value": value}


def _public_key_config(
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
) -> str:
    """Return the public key configuration value as sent by the api."""
    encoded_key = base64.b64encode(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()
    return orjson.dumps({"publicKey": encoded_key}).decode()


def _successful_responses(private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    """Return the responses of a successful login and device verification."""
    user = {"code": "0000", "data": {"uid": "user-id", "accessToken": "access-token"}}
    return {
        "login": user,
        "loginCheckMobile": user,
        "verifyDevice": user,
        "sendEmailVerifyCode": {"code": "0000", "data": {"verifyId": "verify-id"}},
        "getAuthCode": {"code": "0000", "data": {"authCode": "auth-code"}},
        "getConfig": {
            "code": "0000",
            "data": [_key_config(_public_key_config(private_key.public_key()))],
        },
        "user.do": {
            "result": "ok",
            "userId": "user-id",
            "token": "portal-token",
            "last": 604800000,
        },
    }


def _decrypt_parameter(
    private_key: rsa.RSAPrivateKey, params: dict[str, Any], parameter: str
) -> str:
    return private_key.decrypt(
        base64.b64decode(params[parameter]), padding.PKCS1v15()
    ).decode()
