"""Exercise the workaround against the upstream fake HTTP API and real RSA code."""

import importlib.util
import logging
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import ClientResponseError, ClientSession
from cryptography.hazmat.primitives.asymmetric import rsa
from deebot_client import authentication
from deebot_client.authentication import _AuthClient, create_rest_config
from deebot_client.exceptions import (
    AuthenticationError,
    DeviceVerificationRequiredError,
    InvalidAuthenticationError,
    InvalidVerificationCodeError,
)
from deebot_client.util import md5

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


patch = load_module(
    "ecovacs_auth_patch", ROOT / "custom_components/ecovacs/auth_patch.py"
)
upstream = load_module("upstream_auth_tests", ROOT / "tests/upstream_auth_helpers.py")
EMAIL = "test@example.com"
PASSWORD = "p@ss-?șț&+word"
DEVICE = "ABC12345"
USER = {"loginResult": "SUCCESS", "uid": "user-id", "accessToken": "access-token"}
RISK = {
    "loginResult": "HIGH_RISK",
    "loginRiskScene": "NEW_DEVICE",
    "riskTicket": "secret-risk-ticket",
}


@pytest_asyncio.fixture
async def setup():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    responses = upstream._successful_responses(key)
    responses.update(
        login2={"code": "0000", "data": USER},
        loginByRiskVerify={"code": "0000", "data": USER},
    )
    api = upstream._FakeEcovacsApi(responses)
    await api.start()
    async with ClientSession() as session:
        config = create_rest_config(
            session, device_id=DEVICE, alpha_2_country="MD", override_rest_url=api.url
        )
        auth = patch.Authenticator(config, EMAIL, PASSWORD)
        try:
            yield api, auth, key, config
        finally:
            await auth.teardown()
    await api.stop()


def assert_signature(request):
    metadata = dict(
        country="md",
        lang="EN",
        deviceId=DEVICE,
        appCode="global_e",
        appVersion="3.17.2",
        channel="google_play",
        deviceType="1",
    )
    params = {
        k: v for k, v in request.query.items() if k not in ("authSign", "authAppkey")
    }
    fields = {**metadata, **params}
    expected = md5(
        authentication._CLIENT_KEY
        + "".join(f"{k}={fields[k]}" for k in sorted(fields))
        + authentication._CLIENT_SECRET
    )
    assert request.query["authSign"] == expected


@pytest.mark.asyncio
async def test_trusted_login_encrypts_plain_password_and_keeps_session(setup):
    api, auth, key, config = setup
    credentials = await auth.authenticate()
    assert credentials.user_id == "user-id"
    (request,) = api.requests["login2"]
    assert (
        request.path
        == f"/v2/private/md/EN/{DEVICE}/global_e/3.17.2/google_play/1/user/login2"
    )
    assert upstream._decrypt_parameter(key, request.query, "encryptAccount") == EMAIL
    assert upstream._decrypt_parameter(key, request.query, "encryptPwd") == PASSWORD
    assert_signature(request)
    assert await auth.authenticate() is credentials
    renewed = patch.Authenticator(
        config, EMAIL, PASSWORD, account_credentials=auth.account_credentials
    )
    try:
        await renewed.authenticate()
        await renewed.authenticate(force=True)
        assert len(api.requests["login2"]) == 1
        assert not api.requests["login"]
    finally:
        await renewed.teardown()


@pytest.mark.asyncio
async def test_email_verification_wrong_code_retry_and_redaction(setup, caplog):
    api, auth, key, _ = setup
    api.responses["login2"] = {"code": "0000", "data": RISK}
    with caplog.at_level(logging.DEBUG, logger="deebot_client.authentication"):
        with pytest.raises(DeviceVerificationRequiredError):
            await auth.authenticate()
        await auth.request_device_verification_code()
        (request,) = api.requests["sendEmailVerifyCode"]
        assert request.path.startswith("/v1/private/md/")
        assert request.query["verifyType"] == "EMAIL_LOGIN_RISK_CHECK"
        assert upstream._decrypt_parameter(key, request.query, "encryptEmail") == EMAIL
        assert_signature(request)
        api.responses["loginByRiskVerify"] = {
            "code": "1012",
            "msg": "Invalid verification code",
        }
        with pytest.raises(InvalidVerificationCodeError):
            await auth.verify_device("000000")
        api.responses["loginByRiskVerify"] = {"code": "0000", "data": USER}
        await auth.verify_device(" 123456 ")
        request = api.requests["loginByRiskVerify"][-1]
        assert request.path.startswith("/v2/private/md/")
        assert request.query["verifyCode"] == "123456"
        assert request.query["riskTicket"] == "secret-risk-ticket"
        assert request.query["verifyId"] == "verify-id"
        assert_signature(request)
        assert auth.account_credentials.access_token == "access-token"
        await auth.authenticate()
    assert len(api.requests["login2"]) == 1
    assert not api.requests["verifyDevice"]
    for secret in (
        PASSWORD,
        EMAIL,
        "secret-risk-ticket",
        "verify-id",
        "access-token",
        "portal-token",
    ):
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_invalid_password_and_http_errors_keep_exception_types(setup):
    api, auth, _, _ = setup
    api.responses["login2"] = {"code": "1005", "msg": "Invalid password"}
    with pytest.raises(InvalidAuthenticationError):
        await auth.authenticate()
    del api.responses["login2"]
    with pytest.raises(ClientResponseError):
        await auth.authenticate()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {"loginResult": "HIGH_RISK", "loginRiskScene": "NEW_DEVICE"},
        {**RISK, "loginRiskScene": "CAPTCHA"},
        {"uid": None, "accessToken": "token"},
        {"loginResult": "FAILURE"},
    ],
)
async def test_malformed_and_unsupported_login_is_rejected(setup, data):
    api, auth, _, _ = setup
    api.responses["login2"] = {"code": "0000", "data": data}
    with pytest.raises(AuthenticationError):
        await auth.authenticate()
    assert not api.requests["sendEmailVerifyCode"]
    assert not api.requests["getAuthCode"]


@pytest.mark.asyncio
async def test_missing_verify_id_prevents_verification(setup):
    api, auth, _, _ = setup
    api.responses["login2"] = {"code": "0000", "data": RISK}
    with pytest.raises(DeviceVerificationRequiredError):
        await auth.authenticate()
    api.responses["sendEmailVerifyCode"] = {"code": "0000", "data": {}}
    with pytest.raises(AuthenticationError, match="verifyId"):
        await auth.request_device_verification_code()
    with pytest.raises(AuthenticationError, match="first"):
        await auth.verify_device("123456")
    assert not api.requests["loginByRiskVerify"]


@pytest.mark.asyncio
async def test_self_hosted_preserves_legacy_password_hash(setup):
    api, _, _, config = setup
    auth = patch.Authenticator(config, EMAIL, PASSWORD, legacy=True)
    try:
        assert type(auth._auth_client) is _AuthClient
        await auth.authenticate()
        assert api.requests["login"][0].query["password"] == md5(PASSWORD)
        assert not api.requests["login2"]
    finally:
        await auth.teardown()


@pytest.mark.asyncio
async def test_china_keeps_original_auth_client(setup):
    _, _, _, config = setup
    config = create_rest_config(config.session, device_id=DEVICE, alpha_2_country="CN")
    auth = patch.Authenticator(config, EMAIL, PASSWORD)
    assert type(auth._auth_client) is _AuthClient
    await auth.teardown()


@pytest.mark.asyncio
async def test_failed_token_renewal_falls_back_to_login_v2(setup):
    api, old, _, config = setup
    await old.authenticate()
    api.responses["getAuthCode"] = {"code": "1005", "msg": "Expired token"}
    auth = patch.Authenticator(
        config, EMAIL, PASSWORD, account_credentials=old.account_credentials
    )
    api.responses["login2"] = {"code": "0000", "data": RISK}
    try:
        with pytest.raises(DeviceVerificationRequiredError):
            await auth.authenticate()
        assert len(api.requests["login2"]) == 2
        assert not api.requests["login"]
    finally:
        await auth.teardown()


@pytest.mark.asyncio
async def test_verification_request_failure_is_not_retried(setup):
    api, auth, _, _ = setup
    api.responses["login2"] = {"code": "0000", "data": RISK}
    with pytest.raises(DeviceVerificationRequiredError):
        await auth.authenticate()
    api.responses["sendEmailVerifyCode"] = {"code": "0003", "msg": "Parameter error"}
    with pytest.raises(AuthenticationError, match="0003"):
        await auth.request_device_verification_code()
    assert len(api.requests["sendEmailVerifyCode"]) == 1
    assert not api.requests["loginByRiskVerify"]
