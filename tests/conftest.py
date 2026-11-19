"""Shared fixtures. Nothing here reaches the network: every login and API call
is replaced, so the suite never sends a request to Rain Bird."""
from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

import pytest

from custom_components.rainbird_iq4 import auth as auth_mod
from custom_components.rainbird_iq4.auth import RainBirdAuth, RainBirdAuthRejected
from custom_components.rainbird_iq4.const import (
    CONF_AUTH_CHANNEL,
    CONF_COMPANY_ID,
    CONF_ENABLE_REALTIME,
    CONF_PASSWORD,
    CONF_SATELLITE_ID,
    CONF_USERNAME,
    DOMAIN,
)
from custom_components.rainbird_iq4.coordinator import (
    RainBirdConfigCoordinator,
    RainBirdCoordinator,
    RainBirdProgramCoordinator,
)
from pytest_homeassistant_custom_component.common import MockConfigEntry

USERNAME = "user@example.com"
OLD_PASSWORD = "old-password-1"
NEW_PASSWORD = "new-password-2"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Let Home Assistant load custom_components/ in every test."""
    yield


def fake_jwt(lifetime: int = 3600) -> str:
    """An unsigned JWT whose only claim is a valid exp."""
    payload = json.dumps({"exp": int(time.time()) + lifetime}).encode()
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"header.{body}.signature"


def rejection() -> RainBirdAuthRejected:
    return RainBirdAuthRejected("Login rejected (test)")


class FakeTime:
    """Stands in for the time module inside auth.py only.

    monotonic() can be moved forward to get past a login backoff; time()
    stays real so token expiry checks behave normally. Patching auth.time
    (the module's own binding) leaves the event loop's clock untouched.
    """

    def __init__(self) -> None:
        self.offset = 0.0

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def monotonic(self) -> float:
        return time.monotonic() + self.offset

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture
def clock():
    fake = FakeTime()
    with patch.object(auth_mod, "time", fake):
        yield fake


@pytest.fixture(autouse=True)
def no_token_cache():
    """Keep tokens in memory only: no reads or writes under .storage."""

    def _load(self):
        self._cache_loaded = True

    with (
        patch.object(RainBirdAuth, "_load_token_cache", _load),
        patch.object(RainBirdAuth, "_save_token_cache", lambda self: None),
    ):
        yield


@pytest.fixture
def token_disk():
    """The on-disk token cache, simulated: one file per cache path, shared
    by every RainBirdAuth instance, as the real one is. Returns the dict."""
    disk: dict[str, dict] = {}

    def _load(self):
        data = disk.get(self._cache_path)
        if data and time.time() < data["exp"] - 60:
            self._token, self._token_exp = data["token"], data["exp"]
        self._cache_loaded = True

    def _save(self):
        disk[self._cache_path] = {"token": self._token, "exp": self._token_exp}

    with (
        patch.object(RainBirdAuth, "_load_token_cache", _load),
        patch.object(RainBirdAuth, "_save_token_cache", _save),
    ):
        yield disk


def seed_valid_cached_token(hass, disk: dict) -> None:
    """Put a valid token for USERNAME/web on the simulated disk, as another
    entry of the same account refreshing it would."""
    path = RainBirdAuth(hass, USERNAME, "any")._cache_path
    disk[path] = {"token": fake_jwt(), "exp": int(time.time()) + 3600}


class FakeRainBird:
    """Accepts one password per account; refuses everything else."""

    def __init__(self, password: str | None) -> None:
        self.password = password
        self.calls: list[str] = []

    def fetch_token(self, username: str, password: str) -> str:
        self.calls.append(password)
        if password != self.password:
            raise rejection()
        return fake_jwt()


@pytest.fixture
def rainbird():
    """Patch the web-channel login. Set .password to the accepted one."""
    fake = FakeRainBird(password=None)
    with patch.object(auth_mod, "fetch_token", side_effect=fake.fetch_token):
        yield fake


def _fake_fetch(self):
    # Logging in is the only part of a poll these tests care about.
    self.api._auth.get_token()
    return {}


def _fake_satellites(self):
    self._auth.get_token()
    return [
        {"id": 1, "companyId": 10, "name": "Front"},
        {"id": 2, "companyId": 10, "name": "Back"},
    ]


@pytest.fixture
def integration(hass):
    """Make async_setup_entry runnable without Rain Bird or the frontend."""
    hass.config.components.add("http")
    with (
        patch.object(RainBirdCoordinator, "_fetch_data", _fake_fetch),
        patch.object(RainBirdConfigCoordinator, "_fetch_data", _fake_fetch),
        patch.object(RainBirdProgramCoordinator, "_fetch_data", _fake_fetch),
        patch(
            "custom_components.rainbird_iq4.api.RainBirdAPI.get_satellite_list",
            _fake_satellites,
        ),
        patch("custom_components.rainbird_iq4.PLATFORMS", []),
        patch("custom_components.rainbird_iq4._async_register_frontend"),
        patch("custom_components.rainbird_iq4._async_schedule_card_resource_version"),
    ):
        yield


def make_entry(hass, satellite_id: int = 1, password: str = OLD_PASSWORD) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=str(satellite_id),
        data={
            CONF_USERNAME: USERNAME,
            CONF_PASSWORD: password,
            CONF_AUTH_CHANNEL: "web",
            CONF_SATELLITE_ID: satellite_id,
            CONF_COMPANY_ID: 10,
        },
        options={CONF_ENABLE_REALTIME: False},
    )
    entry.add_to_hass(hass)
    return entry


def reauth_flows(hass, entry) -> list[dict]:
    return [
        flow
        for flow in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        if flow["context"].get("source") == "reauth"
        and flow["context"].get("entry_id") == entry.entry_id
    ]
