# Ecovacs login v2: temporary Home Assistant workaround

Temporary custom component for **Home Assistant Core 2026.11.3**, using
`deebot-client==18.7.0`. It addresses `0003 (Parameter error)` from
`user/sendEmailVerifyCode` during setup after the old login requests device
verification with code `1013`.

**A user confirmed successful setup and operation on Home Assistant OS with
the Moldova cloud region after installing this exact package.** This is a
community workaround, not an official Home Assistant release.

## Download and install

Download **`ecovacs-ha-2026.11.3-login-v2.zip`** from the
[release page](https://github.com/Nikba-Creative-Studio/ha-ecovacs-login-v2/releases/tag/v2026.11.3.1).
The ZIP contains the `custom_components` directory; extract it into `/config`,
not into `/config/custom_components`.

1. Create a Home Assistant backup. If you already have
   `/config/custom_components/ecovacs`, save it outside `custom_components`
   before replacing it.
2. Extract the ZIP so these files exist:

   ```text
   /config/custom_components/ecovacs/manifest.json
   /config/custom_components/ecovacs/auth_patch.py
   /config/custom_components/ecovacs/translations/en.json
   ```

3. Fully restart Home Assistant.
4. Add or reauthenticate Ecovacs using your ECOVACS HOME account and account
   region. Enter the email verification code when requested.

Keep 2FA enabled if you already use it. The normal Home Assistant warning for
a custom integration is expected. English UI translations are included.

ZIP SHA-256:

```text
4759ab12b5c4cc3dca2931ebea8f153e7f92949b502895f6ea50899d385dfcb3
```

## What changes

The adapter uses the app's newer cloud authentication flow:

1. `v2/user/login2`, encrypting the original account and password with the
   server's RSA key. Encrypting the old MD5 password hash does not satisfy v2.
2. A `HIGH_RISK` / `NEW_DEVICE` response retains the `riskTicket` and requests
   an email code using `EMAIL_LOGIN_RISK_CHECK`.
3. `v2/user/loginByRiskVerify` uses that ticket, the returned `verifyId`, and
   the email code to finish login.

The existing library handles token exchange, renewal, locks, timers and
credential callbacks. Both HA authenticator callers use the adapter; no new
runtime dependency is added. Extra log filtering masks the new sensitive
fields. Self-hosted and China connections retain the original authentication
client; their live operation has not been tested here.

The component starts from the official Core 2026.11.3 sources. Only
`config_flow.py`, `controller.py` and `manifest.json` change; `auth_patch.py`
and English translations are added. The exact deployment diff is in
[`dist/ecovacs-login-v2.patch`](dist/ecovacs-login-v2.patch).

## Validation and limits

- **14 automated tests passed** against a local HTTP server using the actual
  pinned library and real RSA encryption: request signatures, trusted login,
  email verification, wrong-code retry, session reuse, failed-token fallback,
  malformed responses, HTTP errors, no automatic retry of a rejected code
  request, legacy selection and log redaction.
- A signed public-key request against the Moldova cloud endpoint succeeded.
- ZIP checksums and CRCs were verified; all 24 installed files were checked
  against the archive before the live installation.
- Live account setup and integration operation were confirmed by the user.
  Cleaning commands, all robot models, other cloud regions and long-term
  renewal against the real service have not been tested.

## Remove after an official fix

Move `/config/custom_components/ecovacs` outside `custom_components` and
restart Home Assistant to load the official integration again. Restore your
previous override if needed. Do not edit `.storage` or remove the robot from
the vendor app.

This adapter depends on **private APIs in deebot-client 18.7.0**. Remove it
before upgrading beyond the supported HA version unless it has been reviewed
again. Cloud API changes may break this workaround.

## Run the tests

Python 3.14 is required. From a clean checkout:

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m pytest -q
```

## Credits and upstream work

- [sdteam-stefano's protocol analysis and successful v2 verification](https://github.com/home-assistant/core/issues/194725#issuecomment-7194181183)
  informed this independently assembled adapter. This download is a valid
  replacement package for users unable to extract the attachment in that
  discussion; it is not a repaired copy of that attachment.
- [Existing upstream login2 PR](https://github.com/DeebotUniverse/client.py/pull/1920).
- [Home Assistant issue #194725](https://github.com/home-assistant/core/issues/194725).
- [Official Core 2026.11.3 component](https://github.com/home-assistant/core/tree/2026.11.3/homeassistant/components/ecovacs)
  and [deebot-client 18.7.0](https://github.com/DeebotUniverse/client.py/tree/18.7.0).

See [NOTICE](NOTICE) and the included licenses for upstream attribution.
