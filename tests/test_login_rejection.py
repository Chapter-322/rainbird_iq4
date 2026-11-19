"""A refused-looking login must not latch on one observation.

Background: Home Assistant asked a user for the password twice in one day,
and the same password was accepted each time. One login-page response was
enough to stop every login and start a reauth flow. These tests pin the
rule that replaced it: reauth only after two consecutive rejections at
least REJECTION_RETRY_DELAY apart, with the count surviving setup retries,
and never shared between entries that hold different passwords.
"""
from __future__ import annotations

import logging
from unittest.mock import patch
from urllib.parse import quote

import pytest

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.data_entry_flow import FlowResultType

from custom_components.rainbird_iq4 import auth as auth_mod
from custom_components.rainbird_iq4.auth import (
    RainBirdAuth,
    RainBirdAuthRejected,
    RainBirdAuthSuspect,
    RainBirdWafChallenge,
    login_state_for,
)
from custom_components.rainbird_iq4.const import (
    AUTH_BASE,
    AUTH_CHANNEL_APP,
    AUTH_CHANNEL_WEB,
    CONF_AUTH_CHANNEL,
    CONF_PASSWORD,
    CONF_USERNAME,
    DOMAIN,
)

from .conftest import (
    NEW_PASSWORD,
    OLD_PASSWORD,
    USERNAME,
    make_entry,
    reauth_flows,
    rejection,
    seed_valid_cached_token,
)

RETRY = 300  # the wait before the second attempt that may trigger reauth


async def _setup(hass, entry) -> None:
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


async def _retry(hass, entry) -> None:
    """What Home Assistant does after ConfigEntryNotReady: a fresh setup,
    with a fresh RainBirdAuth instance."""
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()


# --- setup and setup retries -------------------------------------------------


async def test_one_rejection_then_success_asks_no_reauth(
    hass, integration, rainbird, clock
):
    entry = make_entry(hass)
    rainbird.password = None  # Rain Bird refuses this once...
    await _setup(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert reauth_flows(hass, entry) == []

    rainbird.password = OLD_PASSWORD  # ...then accepts the same password
    clock.advance(RETRY + 1)
    await _retry(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert reauth_flows(hass, entry) == []
    assert rainbird.calls == [OLD_PASSWORD, OLD_PASSWORD]


async def test_rejection_on_first_refresh_and_on_setup_retry_asks_reauth(
    hass, integration, rainbird, clock
):
    entry = make_entry(hass)
    await _setup(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY

    clock.advance(RETRY + 1)
    await _retry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert len(reauth_flows(hass, entry)) == 1
    assert rainbird.calls == [OLD_PASSWORD, OLD_PASSWORD]


async def test_setup_retry_inside_the_wait_does_not_log_in(
    hass, integration, rainbird, clock
):
    entry = make_entry(hass)
    await _setup(hass, entry)

    clock.advance(RETRY - 60)
    await _retry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert reauth_flows(hass, entry) == []
    assert rainbird.calls == [OLD_PASSWORD]


async def test_latched_rejection_stops_logins_across_setup_retries(
    hass, integration, rainbird, clock
):
    entry = make_entry(hass)
    await _setup(hass, entry)
    clock.advance(RETRY + 1)
    await _retry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_ERROR

    clock.advance(3600)
    await _retry(hass, entry)
    assert rainbird.calls == [OLD_PASSWORD, OLD_PASSWORD]


# --- the counter itself ------------------------------------------------------


async def test_successful_login_resets_the_rejection_count(hass, rainbird, clock):
    auth = RainBirdAuth(hass, USERNAME, OLD_PASSWORD)

    rainbird.password = None
    with pytest.raises(Exception) as first:
        await hass.async_add_executor_job(auth.get_token)
    assert not isinstance(first.value, RainBirdAuthRejected)

    rainbird.password = OLD_PASSWORD
    clock.advance(RETRY + 1)
    await hass.async_add_executor_job(auth.get_token)

    rainbird.password = None
    auth.invalidate()
    with pytest.raises(Exception) as again:
        await hass.async_add_executor_job(auth.get_token)
    assert not isinstance(again.value, RainBirdAuthRejected)


# --- config flow and reauth --------------------------------------------------


async def test_config_flow_reports_invalid_auth_on_one_rejection(
    hass, integration, rainbird
):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_USERNAME: USERNAME, CONF_PASSWORD: "typo",
         CONF_AUTH_CHANNEL: AUTH_CHANNEL_WEB},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}


async def _latch(hass, entry, clock) -> None:
    await _setup(hass, entry)
    clock.advance(RETRY + 1)
    await _retry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_ERROR


async def test_reauth_accepts_a_correct_password_right_after_a_typo(
    hass, integration, rainbird, clock
):
    entry = make_entry(hass)
    await _latch(hass, entry, clock)
    rainbird.password = NEW_PASSWORD
    (flow,) = reauth_flows(hass, entry)

    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_PASSWORD: "typo"}
    )
    assert result["errors"] == {"base": "invalid_auth"}

    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_PASSWORD: NEW_PASSWORD}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED


async def test_reauth_with_the_same_password_clears_the_latch(
    hass, integration, rainbird, clock
):
    """The reported case: the stored password was right all along."""
    entry = make_entry(hass)
    await _latch(hass, entry, clock)
    rainbird.password = OLD_PASSWORD
    (flow,) = reauth_flows(hass, entry)

    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_PASSWORD: OLD_PASSWORD}
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert reauth_flows(hass, entry) == []


async def _two_latched_entries(hass, clock):
    front = make_entry(hass, satellite_id=1)
    back = make_entry(hass, satellite_id=2)
    await _latch(hass, front, clock)
    await _retry(hass, back)  # same credentials: meets the shared latch
    assert back.state is ConfigEntryState.SETUP_ERROR
    assert len(reauth_flows(hass, back)) == 1
    return front, back


async def test_reauth_of_one_entry_fixes_every_entry_of_the_account(
    hass, integration, rainbird, clock
):
    """The reported case (two ESP-TM2 on one account): one prompt per entry,
    so the user re-entered the same password twice. One reauth must do."""
    front, back = await _two_latched_entries(hass, clock)
    rainbird.password = NEW_PASSWORD

    (flow,) = reauth_flows(hass, front)
    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_PASSWORD: NEW_PASSWORD}
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()

    for entry in (front, back):
        assert entry.state is ConfigEntryState.LOADED
        assert entry.data[CONF_PASSWORD] == NEW_PASSWORD
        assert reauth_flows(hass, entry) == []


async def test_reporter_case_same_correct_password_on_two_controllers(
    hass, integration, rainbird, clock, token_disk
):
    """Issue #22 as reported: the password never changed and was right.

    Both entries latched on spurious rejections; re-entering the same
    password once must bring both back, with a single login after the
    submit (the reloaded entries reuse the token the reauth saved).
    """
    front, back = await _two_latched_entries(hass, clock)
    rainbird.password = OLD_PASSWORD
    logins_before = len(rainbird.calls)

    (flow,) = reauth_flows(hass, front)
    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_PASSWORD: OLD_PASSWORD}
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()

    for entry in (front, back):
        assert entry.state is ConfigEntryState.LOADED
        assert reauth_flows(hass, entry) == []
    assert len(rainbird.calls) - logins_before == 1


async def test_reauth_with_a_wrong_password_and_a_cached_token_changes_nothing(
    hass, integration, rainbird, clock, token_disk
):
    """Propagating a password is only safe because the reauth really logs in:
    a valid token on disk must not stand in for checking the password."""
    front, back = await _two_latched_entries(hass, clock)
    rainbird.password = NEW_PASSWORD
    seed_valid_cached_token(hass, token_disk)

    (flow,) = reauth_flows(hass, front)
    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_PASSWORD: "wrong"}
    )
    assert result["errors"] == {"base": "invalid_auth"}
    assert rainbird.calls[-1] == "wrong"
    await hass.async_block_till_done()
    assert front.data[CONF_PASSWORD] == OLD_PASSWORD
    assert back.data[CONF_PASSWORD] == OLD_PASSWORD


async def test_user_step_with_a_cached_token_still_checks_the_password(
    hass, integration, rainbird, token_disk
):
    seed_valid_cached_token(hass, token_disk)
    rainbird.password = OLD_PASSWORD

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_USERNAME: USERNAME, CONF_PASSWORD: "wrong",
         CONF_AUTH_CHANNEL: AUTH_CHANNEL_WEB},
    )
    assert result["errors"] == {"base": "invalid_auth"}
    assert rainbird.calls == ["wrong"]


async def test_adding_a_controller_with_a_working_login_clears_a_stale_latch(
    hass, integration, rainbird, clock
):
    front = make_entry(hass, satellite_id=1)
    await _latch(hass, front, clock)
    rainbird.password = OLD_PASSWORD  # the latch was wrong all along

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_USERNAME: USERNAME, CONF_PASSWORD: OLD_PASSWORD,
         CONF_AUTH_CHANNEL: AUTH_CHANNEL_WEB},
    )
    assert result["step_id"] == "select_controller"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"satellite_id": "2"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert result["result"].state is ConfigEntryState.LOADED


async def test_reauth_of_a_loaded_entry_reloads_it_once(
    hass, integration, rainbird, caplog
):
    """A loaded entry has an update listener; HA warns about
    async_update_reload_and_abort on such entries (announced to break in
    2026.12) because it reloads them twice."""
    rainbird.password = OLD_PASSWORD
    entry = make_entry(hass)
    await _setup(hass, entry)
    assert entry.state is ConfigEntryState.LOADED

    rainbird.password = NEW_PASSWORD
    entry.async_start_reauth(hass)
    await hass.async_block_till_done()
    (flow,) = reauth_flows(hass, entry)

    with patch.object(
        hass.config_entries, "async_reload", wraps=hass.config_entries.async_reload
    ) as reload:
        result = await hass.config_entries.flow.async_configure(
            flow["flow_id"], {CONF_PASSWORD: NEW_PASSWORD}
        )
        await hass.async_block_till_done()
    assert result["reason"] == "reauth_successful"
    assert reload.call_count == 1
    assert "update listener" not in caplog.text
    assert entry.state is ConfigEntryState.LOADED
    assert entry.data[CONF_PASSWORD] == NEW_PASSWORD


async def test_login_state_is_per_password_and_ignores_username_case(hass):
    old = login_state_for(hass, USERNAME, AUTH_CHANNEL_WEB, OLD_PASSWORD)
    assert login_state_for(hass, USERNAME.upper(), AUTH_CHANNEL_WEB, OLD_PASSWORD) is old
    assert login_state_for(hass, USERNAME, AUTH_CHANNEL_WEB, NEW_PASSWORD) is not old
    assert login_state_for(hass, USERNAME, AUTH_CHANNEL_APP, OLD_PASSWORD) is not old


async def test_a_waf_challenge_between_rejections_does_not_reset_the_count(
    hass, clock
):
    auth = RainBirdAuth(hass, USERNAME, OLD_PASSWORD)
    with patch.object(
        auth_mod, "fetch_token",
        side_effect=[rejection(), RainBirdWafChallenge("challenge"), rejection()],
    ):
        with pytest.raises(RainBirdAuthSuspect):
            await hass.async_add_executor_job(auth.get_token)
        clock.advance(RETRY + 1)
        with pytest.raises(RainBirdWafChallenge):
            await hass.async_add_executor_job(auth.get_token)
        clock.advance(3600)
        with pytest.raises(RainBirdAuthRejected):
            await hass.async_add_executor_job(auth.get_token)


async def test_removing_an_entry_clears_its_login_state(
    hass, integration, rainbird, clock
):
    entry = make_entry(hass)
    await _latch(hass, entry, clock)
    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()

    rainbird.password = OLD_PASSWORD
    again = make_entry(hass)
    await _setup(hass, again)
    assert again.state is ConfigEntryState.LOADED


# --- what the rejection logs -------------------------------------------------

_CSRF_PAGE = (
    '<form><input name="__RequestVerificationToken" type="hidden" '
    'value="csrf-123" /></form>'
)
_REFUSED_PAGE = (
    "<html><body><form>"
    '<div class="validation-summary-errors" data-valmsg-summary="true">'
    "<ul><li>Invalid username or password for USER@Example.COM</li></ul></div>"
    '<input name="Username" value="User@Example.com" />'
    "</form></body></html>"
)
_LOGIN_URL = f"{AUTH_BASE}/Account/Login?ReturnUrl={quote('/connect/authorize?state=ABC', safe='')}"


class _Resp:
    def __init__(self, text: str, url: str = _LOGIN_URL, status: int = 200):
        self.text = text
        self.url = url
        self.status_code = status
        self.headers: dict = {}


class _Session:
    def __init__(self, refused_page: str):
        self._refused_page = refused_page

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, **kwargs):
        return _Resp(_CSRF_PAGE, url=url)

    def post(self, url, **kwargs):
        return _Resp(self._refused_page, url=url)


async def _refused_login(hass, channel: str, page: str) -> None:
    auth = RainBirdAuth(hass, USERNAME, OLD_PASSWORD, channel=channel)
    with patch.object(auth_mod.cf, "Session", lambda **kw: _Session(page)):
        with pytest.raises(Exception):
            await hass.async_add_executor_job(auth.get_token)


@pytest.mark.parametrize("channel", [AUTH_CHANNEL_WEB, AUTH_CHANNEL_APP])
async def test_rejection_warning_shows_the_page_error_without_credentials(
    hass, caplog, clock, channel
):
    caplog.set_level(logging.DEBUG, logger="custom_components.rainbird_iq4")
    await _refused_login(hass, channel, _REFUSED_PAGE)

    warnings = "\n".join(
        r.getMessage() for r in caplog.records if r.levelno == logging.WARNING
    )
    assert "Invalid username or password for <user>" in warnings
    assert "HTTP 200" in warnings
    assert "/coreidentityserver/Account/Login" in warnings

    everything = caplog.text
    assert USERNAME.lower() not in everything.lower()
    assert OLD_PASSWORD not in everything
    assert "ReturnUrl" not in everything
    assert "csrf-123" not in everything


async def test_rejection_warning_masks_a_password_shown_on_the_page(
    hass, caplog, clock
):
    page = (
        '<div class="alert alert-danger">Password '
        f"{OLD_PASSWORD} is not valid for {USERNAME.upper()}</div>"
    )
    await _refused_login(hass, AUTH_CHANNEL_WEB, page)
    assert "Password <password> is not valid for <user>" in caplog.text
    assert OLD_PASSWORD not in caplog.text


async def test_rejection_warning_says_when_the_page_has_no_error(hass, caplog, clock):
    await _refused_login(hass, AUTH_CHANNEL_WEB, "<html><form></form></html>")
    assert "no error text" in caplog.text
