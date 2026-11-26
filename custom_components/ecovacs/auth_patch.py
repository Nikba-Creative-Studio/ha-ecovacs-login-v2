"""Temporary Ecovacs cloud login v2 support for HA Core 2026.11.3."""

from typing import Any
from urllib.parse import urljoin

from deebot_client import authentication
from deebot_client.authentication import Authenticator as BaseAuthenticator
from deebot_client.authentication import RestConfiguration, _AuthClient
from deebot_client.exceptions import (
    AuthenticationError,
    DeviceVerificationRequiredError,
)
from deebot_client.logging_filter import SanitizeFilter
from deebot_client.models import AccountCredentials, Credentials
from deebot_client.util import md5


class _RiskDataFilter(SanitizeFilter):
    _SANITIZE_LOG_KEYS = (
        *SanitizeFilter._SANITIZE_LOG_KEYS,
        "risk",
        "verify",
        "encrypt",
        "password",
        "account",
    )


authentication._LOGGER.addFilter(_RiskDataFilter())


def _required_string(data: dict[str, Any], key: str) -> str:
    if not isinstance(value := data.get(key), str) or not value:
        raise AuthenticationError(f"Invalid Ecovacs response: missing {key}")
    return value


# shortcut: private deebot-client 18.7.0 APIs, remove when Core supports login v2.
class _RiskAuthClient(_AuthClient):
    def __init__(self, config, account_id, password, *, on_account_credentials):
        super().__init__(
            config, account_id, "", on_account_credentials=on_account_credentials
        )
        self._password = password
        self._meta["appVersion"] = "3.17.2"
        self._risk_ticket: str | None = None
        self._verify_id: str | None = None

    async def _request(
        self, endpoint: str, params: dict[str, str], *, version: int = 1
    ) -> dict[str, Any]:
        path = authentication._PRIVATE_API_PATH_FORMAT.format(
            endpoint=endpoint, **self._meta
        )
        if version == 2:
            path = path.replace("/v1/", "/v2/", 1)
        response = await self._AuthClient__do_auth_response(
            urljoin(self._config.login_url, path),
            self._AuthClient__sign(
                {**params, **self._AuthClient__request_metadata()},
                self._meta,
                authentication._CLIENT_KEY,
                authentication._CLIENT_SECRET,
            ),
        )
        return self._AuthClient__expect_dict(
            response, "Invalid Ecovacs login v2 response"
        )

    async def login(self) -> Credentials:
        self._risk_ticket = self._verify_id = None
        data = await self._request(
            "user/login2",
            {
                "encryptAccount": await self._AuthClient__encrypt_account(
                    self._account_id
                ),
                "encryptPwd": await self._AuthClient__encrypt_account(self._password),
            },
            version=2,
        )
        if data.get("loginResult") == "HIGH_RISK":
            if data.get("loginRiskScene") != "NEW_DEVICE":
                raise AuthenticationError("Unsupported Ecovacs login verification step")
            self._risk_ticket = _required_string(data, "riskTicket")
            raise DeviceVerificationRequiredError("Ecovacs email verification required")
        return await self._complete_login(data)

    async def request_device_verification_code(self) -> None:
        if not self._risk_ticket:
            raise AuthenticationError("Start Ecovacs login before requesting a code")
        self._verify_id = None
        data = await self._request(
            "user/sendEmailVerifyCode",
            {
                "encryptEmail": await self._AuthClient__encrypt_account(
                    self._account_id
                ),
                "verifyType": "EMAIL_LOGIN_RISK_CHECK",
                "supportChar": "N",
                "isForce": "N",
            },
        )
        self._verify_id = _required_string(data, "verifyId")

    async def verify_device(self, verification_code: str) -> Credentials:
        if not self._risk_ticket or not self._verify_id:
            raise AuthenticationError(
                "Request an Ecovacs email verification code first"
            )
        data = await self._request(
            "user/loginByRiskVerify",
            {
                "riskTicket": self._risk_ticket,
                "encryptEmail": await self._AuthClient__encrypt_account(
                    self._account_id
                ),
                "verifyId": self._verify_id,
                "verifyCode": verification_code.strip(),
            },
            version=2,
        )
        credentials = await self._complete_login(data)
        self._risk_ticket = self._verify_id = None
        return credentials

    async def _complete_login(self, data: dict[str, Any]) -> Credentials:
        if data.get("loginResult") not in (None, "SUCCESS"):
            raise AuthenticationError("Ecovacs login did not succeed")
        _required_string(data, "uid")
        _required_string(data, "accessToken")
        return await self._AuthClient__complete_login(
            data, "Invalid Ecovacs login response"
        )


class Authenticator(BaseAuthenticator):
    """Keep upstream token renewal, locking, callbacks and legacy server support."""

    def __init__(
        self,
        config: RestConfiguration,
        account_id: str,
        password: str,
        *,
        account_credentials: AccountCredentials | None = None,
        legacy: bool = False,
    ) -> None:
        super().__init__(
            config, account_id, md5(password), account_credentials=account_credentials
        )
        if not legacy and config.country.upper() != "CN":
            self._auth_client = _RiskAuthClient(
                config,
                account_id,
                password,
                on_account_credentials=self._set_account_credentials,
            )
