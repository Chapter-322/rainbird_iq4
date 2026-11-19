"""Rain Bird IQ4 authentication using curl_cffi to bypass AWS WAF."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import html
import json
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import parse_qs, quote, urljoin, urlparse

from curl_cffi import requests as cf

from homeassistant.core import HomeAssistant
from homeassistant.util.hass_dict import HassKey

from .const import (
    APP_CLIENT_ID,
    APP_CLIENT_SECRET,
    APP_REDIRECT_URI,
    APP_SCOPE,
    AUTH_BASE,
    AUTH_CHANNEL_APP,
    AUTH_CHANNEL_WEB,
    CLIENT_ID,
    CONF_AUTH_CHANNEL,
    CONF_PASSWORD,
    CONF_USERNAME,
    DEFAULT_AUTH_CHANNEL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

_MAX_REDIRECTS = 10

# AWS WAF serves its JavaScript challenge instead of the real page. It
# answers with 202 (challenge issued), and sometimes 405/429 under load.
# The challenge body always carries one of these markers, so a 200 that
# contains them is a challenge too.
_WAF_STATUS = frozenset({202, 405, 429})
_WAF_MARKERS = ("gokuProps", "challenge.js", "awswaf", "token.awswaf.com")

_WAF_MESSAGE = (
    "AWS WAF served a JavaScript challenge instead of the Rain Bird login "
    "page (HTTP {status}). This is not a credentials problem — the request "
    "never reached the login form. It is usually intermittent; wait a few "
    "minutes and try again."
)


class RainBirdWafChallenge(RuntimeError):
    """AWS WAF intercepted the request with a JavaScript challenge.

    Subclasses RuntimeError so existing callers that only catch
    RuntimeError keep working unchanged.
    """


class RainBirdAuthRejected(RuntimeError):
    """The identity server returned the login page instead of a token.

    Can mean the credentials were refused, or the account is in a state that
    needs attention in the web portal (forced password change, accepting
    new terms, temporary lockout). It is NOT proof of a wrong password: the
    login page also comes back for reasons that pass on their own, which is
    why RainBirdAuth only lets this reach callers after
    REJECTIONS_TO_REAUTH consecutive ones. Callers treat it as final and ask
    the user to reauthenticate.

    status, path and error_text describe the response for the log. path has
    no query string and error_text has the username masked, so both are
    safe to log.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        path: str | None = None,
        error_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.path = path
        self.error_text = error_text


class RainBirdAuthSuspect(RuntimeError):
    """The login page came back, but not often enough yet to ask for reauth.

    Deliberately not a RainBirdAuthRejected subclass: the coordinators turn
    that one into ConfigEntryAuthFailed, and one observation is not enough
    to bother the user. This one is an ordinary failure: the coordinators
    count it as transient and the subscription reconnects with its backoff.
    The config flow still maps it to invalid_auth, since there the user has
    just typed the password.
    """


class RainBirdLoginBackoff(RuntimeError):
    """A login is not attempted because a recent one failed.

    Raised without touching the network while the backoff after a failed
    login (WAF challenge, network error, login page returned) is running.
    """


# Seconds to wait before the next login attempt after the 1st, 2nd and
# 3rd-or-later consecutive failure. Applies only to logins, never to regular
# API calls, and resets on the first successful login. Repeated logins from
# one IP are what escalates the AWS WAF to its JavaScript challenge.
LOGIN_BACKOFF = (60, 300, 900)

# Consecutive login-page responses before the credentials count as refused.
# Must stay above 1: a single one has turned out to be wrong in practice, and
# every reauth it triggers makes the user re-enter a correct password.
REJECTIONS_TO_REAUTH = 2
# Minimum wait after a login-page response before trying again. Long enough
# for a passing problem on Rain Bird's side to clear, short enough that a
# truly changed password is reported within minutes.
REJECTION_RETRY_DELAY = 300

# Longest page error text kept for the log.
_ERROR_TEXT_MAX = 200
# Where ASP.NET / IdentityServer login pages put their error messages.
_ERROR_BLOCK = re.compile(
    r'<(div|span|ul|p)\b[^>]*class="[^"]*\b'
    r'(?:validation-summary-errors|alert-danger|field-validation-error|text-danger)'
    r'\b[^"]*"[^>]*>(.*?)</\1>',
    re.IGNORECASE | re.DOTALL,
)
_TAG = re.compile(r"<[^>]+>")


def _login_page_error(page: str, username: str, password: str) -> str | None:
    """Return the error text a login page shows, safe to log, or None.

    Only the error blocks are read, never the form (it echoes the username).
    The password and the username are masked anyway, case-insensitively for
    the username, before the text is cut, so a cut can never leave a
    readable piece of either.
    """
    parts = []
    for match in _ERROR_BLOCK.finditer(page or ""):
        text = " ".join(html.unescape(_TAG.sub(" ", match.group(2))).split())
        if text:
            parts.append(text)
    if not parts:
        return None
    text = " | ".join(parts)
    if password:
        text = text.replace(password, "<password>")
    user = username.strip()
    if user:
        text = re.sub(re.escape(user), "<user>", text, flags=re.IGNORECASE)
    return text[:_ERROR_TEXT_MAX]


def _login_page_rejection(message: str, resp, username: str, password: str) -> RainBirdAuthRejected:
    """Build the rejection for a login-page response, with what to log."""
    try:
        page = resp.text or ""
    except Exception:
        page = ""
    return RainBirdAuthRejected(
        message,
        status=resp.status_code,
        # Path only: the query carries ReturnUrl with state and nonce.
        path=urlparse(str(resp.url or "")).path,
        error_text=_login_page_error(page, username, password),
    )


def _looks_like_waf(resp) -> bool:
    """Return True if the response is an AWS WAF challenge rather than content."""
    if resp.status_code in _WAF_STATUS:
        return True
    try:
        body = resp.text or ""
    except Exception:
        return False
    return any(marker in body for marker in _WAF_MARKERS)


def _extract_csrf(resp) -> str:
    """Validate a login-page response and return its CSRF token.

    Shared by both auth channels so the WAF is reported identically
    whichever one the user picked.
    """
    if _looks_like_waf(resp):
        raise RainBirdWafChallenge(_WAF_MESSAGE.format(status=resp.status_code))
    if resp.status_code != 200:
        raise RuntimeError(f"Login page failed: HTTP {resp.status_code}")

    match = re.search(
        r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', resp.text
    )
    if not match:
        raise RuntimeError("CSRF token not found in login page")
    return match.group(1)


def _decode_jwt_exp(token: str) -> int:
    """Extract expiration timestamp from JWT payload."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return int(claims.get("exp", 0))
    except Exception:
        return 0


def fetch_token(username: str, password: str) -> str:
    """
    Authenticate with Rain Bird IQ4 and return a JWT access token.

    Uses curl_cffi to impersonate a real Chrome browser and bypass
    the AWS WAF challenge that blocks standard HTTP clients.
    """
    state = secrets.token_hex(8).upper()
    nonce = secrets.token_hex(8).upper()

    return_url_raw = (
        f"/coreidentityserver/connect/authorize/callback"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri=https%3A%2F%2Fiq4.rainbird.com%2Fauth.html"
        f"&response_type=id_token%20token"
        f"&scope=coreAPI.read%20coreAPI.write%20openid%20profile"
        f"&state={state}&nonce={nonce}"
    )

    return_url_encoded = quote(return_url_raw, safe="")
    login_url = f"{AUTH_BASE}/Account/Login?ReturnUrl={return_url_encoded}"

    with cf.Session(impersonate="chrome") as session:
        # Step 1: load login page and extract CSRF token
        csrf = _extract_csrf(session.get(login_url))

        # Step 2: submit credentials
        r2 = session.post(
            login_url,
            data={
                "Username": username,
                "Password": password,
                "ReturnUrl": return_url_raw,
                "__RequestVerificationToken": csrf,
            },
            allow_redirects=True,
        )

        # Step 3: extract access_token from redirect URL fragment
        url = r2.url
        if "access_token=" in url:
            fragment = url.split("#")[1] if "#" in url else url.split("?")[1]
            params = dict(p.split("=", 1) for p in fragment.split("&") if "=" in p)
            token = params.get("access_token")
            if token:
                _LOGGER.debug("Successfully obtained Rain Bird access token")
                return token

        # No token. Work out why before reporting it, so the user is not
        # sent chasing their password when the WAF is what blocked them.
        if _looks_like_waf(r2):
            raise RainBirdWafChallenge(_WAF_MESSAGE.format(status=r2.status_code))

        if "/Account/Login" in url:
            raise _login_page_rejection(
                "Login rejected (the server returned the login page instead of "
                "redirecting with a token). Check the username and password, and "
                "try logging in at https://iq4.rainbird.com — the account may need "
                "a password change or new terms accepted.",
                r2, username, password,
            )

        raise RuntimeError(
            f"access_token not found in redirect. "
            f"HTTP {r2.status_code}, URL: {r2.url[:200]}"
        )


def _make_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (code_verifier, code_challenge) pair using S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def fetch_token_isapp(username: str, password: str) -> str:
    """
    Authenticate the way the official Rain Bird 2.0 mobile app does and
    return a JWT access token.

    Uses the Authorization Code + PKCE flow with the mobile app's OAuth
    client. The resulting token carries isApp: true / isIQ: false, which
    (unlike the web-portal token) is not subject to the US free-tier
    "0 controllers" cap, so it can issue zone-control commands that the
    web channel rejects with 403.

    Uses curl_cffi to impersonate Chrome and bypass the AWS WAF challenge.
    """
    state = secrets.token_hex(8).upper()
    nonce = secrets.token_hex(8).upper()
    code_verifier, code_challenge = _make_pkce_pair()

    return_url_raw = (
        f"/coreidentityserver/connect/authorize/callback"
        f"?client_id={APP_CLIENT_ID}"
        f"&redirect_uri={quote(APP_REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&scope={quote(APP_SCOPE, safe='')}"
        f"&state={state}&nonce={nonce}"
    )
    login_url = f"{AUTH_BASE}/Account/Login?ReturnUrl={quote(return_url_raw, safe='')}"

    with cf.Session(impersonate="chrome") as session:
        # Step 1: load login page and extract CSRF token
        csrf = _extract_csrf(session.get(login_url))

        # Step 2: submit credentials without auto-following redirects; we
        # need to intercept the authorization code, which lands on a
        # non-http redirect URI (com.rainbird.mobile://auth) the client
        # cannot follow itself.
        resp = session.post(
            login_url,
            data={
                "Username": username,
                "Password": password,
                "ReturnUrl": return_url_raw,
                "__RequestVerificationToken": csrf,
            },
            allow_redirects=False,
        )

        if not (resp.headers.get("location") or resp.headers.get("Location")):
            if _looks_like_waf(resp):
                raise RainBirdWafChallenge(
                    _WAF_MESSAGE.format(status=resp.status_code)
                )
            if resp.status_code == 200:
                raise _login_page_rejection(
                    "Login rejected (the server returned the login page instead "
                    "of redirecting). Check the username and password, and try "
                    "logging in at https://iq4.rainbird.com — the account may "
                    "need a password change or new terms accepted.",
                    resp, username, password,
                )

        # Step 3: walk the redirect chain until the authorization code appears
        code = None
        current_url = login_url
        for _ in range(_MAX_REDIRECTS):
            location = resp.headers.get("location") or resp.headers.get("Location")
            if not location:
                raise RuntimeError(
                    f"No redirect while logging in (HTTP {resp.status_code})."
                )
            absolute = urljoin(current_url, location)
            parsed = urlparse(absolute)
            found = parse_qs(parsed.query).get("code", [None])[0]
            if found:
                code = found
                break
            if parsed.scheme not in ("http", "https"):
                raise RuntimeError(
                    f"Reached final redirect but found no authorization code: {absolute}"
                )
            current_url = absolute
            resp = session.get(current_url, allow_redirects=False)

        if not code:
            raise RuntimeError("Too many redirects while logging in — no code found.")

        # Step 4: exchange the code for a token using the app client secret
        basic = base64.b64encode(
            f"{APP_CLIENT_ID}:{APP_CLIENT_SECRET}".encode()
        ).decode()
        token_resp = session.post(
            f"{AUTH_BASE}/connect/token",
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "*/*",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": APP_REDIRECT_URI,
            },
        )
        if token_resp.status_code != 200:
            raise RuntimeError(
                f"Token exchange failed: HTTP {token_resp.status_code}, "
                f"body: {token_resp.text[:200]}"
            )

        token = token_resp.json().get("access_token")
        if not token:
            raise RuntimeError("Token exchange succeeded but no access_token returned.")

        _LOGGER.debug("Successfully obtained Rain Bird app-channel access token")
        return token


@dataclass
class LoginState:
    """Login bookkeeping that must outlive a RainBirdAuth instance.

    A failure in the first refresh ends in ConfigEntryNotReady, and Home
    Assistant retries the setup with a brand-new RainBirdAuth. Bookkeeping
    kept on the instance would restart at zero on every retry: the backoff
    would never hold and a refused password would be resent forever. So
    async_setup_entry takes this from hass.data (see login_state_for) and
    every instance for the same account, channel and password shares it.
    """

    # Serializes logins: the three coordinators poll from different executor
    # threads, and without it an expired token can trigger simultaneous
    # logins. Shared, so entries with the same credentials serialize too.
    refresh_lock: threading.Lock = field(default_factory=threading.Lock)
    # Consecutive login-page responses since the last successful login.
    rejections: int = 0
    # Set once rejections reaches REJECTIONS_TO_REAUTH. From then on no login
    # is attempted at all: retrying a refused password every poll is what
    # gets an account locked or the IP challenged by the WAF.
    rejected: RainBirdAuthRejected | None = None
    # Backoff after any failed login.
    login_failures: int = 0
    next_login_at: float = 0.0

    def reset(self) -> None:
        """Forget every failure, as after a successful login.

        Called from the event loop, so it must not take refresh_lock (it is
        held across a network login). Plain attribute writes: at worst a
        login already in flight overwrites them with its own outcome, which
        is just as current.
        """
        self.rejections = 0
        self.rejected = None
        self.login_failures = 0
        self.next_login_at = 0.0


# hass.data key of the shared LoginState objects. Kept out of
# hass.data[DOMAIN], which holds only one dict per loaded entry: the service
# helpers iterate it and the unload path checks it is empty.
LOGIN_STATE: HassKey[dict[str, LoginState]] = HassKey(f"{DOMAIN}_login")


def _login_state_key(username: str, channel: str, password: str) -> str:
    """Key of the LoginState for one set of credentials.

    The password is part of it: two entries for the same account where only
    one got the new password after a change must not share a latch, or the
    one still refused would keep sending the other back to reauth. The key
    lives in memory only and must never be logged.
    """
    raw = f"{username.strip().lower()}|{channel}|{password}"
    return hashlib.sha256(raw.encode()).hexdigest()


def entry_credentials(entry) -> tuple[str, str, str]:
    """(username, channel, password) a config entry logs in with.

    The channel chosen at install (entry.data) can be overridden later in
    the options flow (entry.options takes precedence).
    """
    channel = entry.options.get(
        CONF_AUTH_CHANNEL,
        entry.data.get(CONF_AUTH_CHANNEL, DEFAULT_AUTH_CHANNEL),
    )
    return entry.data[CONF_USERNAME], channel, entry.data[CONF_PASSWORD]


def login_state_for(
    hass: HomeAssistant, username: str, channel: str, password: str
) -> LoginState:
    """Return the shared LoginState for these credentials, creating it."""
    states = hass.data.setdefault(LOGIN_STATE, {})
    return states.setdefault(
        _login_state_key(username, channel, password), LoginState()
    )


def reset_login_state(
    hass: HomeAssistant, username: str, channel: str, password: str
) -> None:
    """Clear the shared LoginState for these credentials, if there is one."""
    state = hass.data.get(LOGIN_STATE, {}).get(
        _login_state_key(username, channel, password)
    )
    if state is not None:
        state.reset()


class RainBirdAuth:
    """
    Manages Rain Bird JWT token lifecycle.

    Caches the token in memory and on disk, and refreshes it automatically
    60 seconds before expiration. Disk cache survives HA restarts and
    integration updates (it lives in the HA config dir, keyed per account).
    All disk I/O happens inside get_token() which runs in an executor thread.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        username: str,
        password: str,
        channel: str = DEFAULT_AUTH_CHANNEL,
        state: LoginState | None = None,
        read_cache: bool = True,
    ) -> None:
        self._username = username
        self._password = password
        self._channel = channel
        self._token: str | None = None
        self._token_exp: int = 0
        # read_cache=False is for checking a password (config flow): the disk
        # cache is keyed by account and channel only, so any valid token in
        # it, e.g. one another entry of the account just refreshed, would
        # "accept" whatever password was typed without asking Rain Bird.
        # Writing stays on: a token from a login that just worked is safe to
        # share, and the entries reloaded after a reauth reuse it instead of
        # each logging in again.
        self._cache_loaded = not read_cache
        # Rejection count, latch, backoff and refresh lock. async_setup_entry
        # passes the shared one from login_state_for, so they survive setup
        # retries. The config flow passes none on purpose: each submit is a
        # password the user just typed, and it must be tried at once even if
        # the stored one is latched or backing off. A successful reauth
        # clears the shared state of the new credentials before reloading.
        self._state = state if state is not None else LoginState()
        # Per-account, per-channel cache file in the HA config dir (survives
        # HACS updates, never mixes tokens between different Rain Bird
        # accounts, and keeps web/app tokens separate so switching channels
        # never reuses a token from the other channel).
        key = f"{username.strip().lower()}|{channel}"
        account_hash = hashlib.sha256(key.encode()).hexdigest()[:12]
        self._cache_path = hass.config.path(
            ".storage", f"rainbird_iq4_token_{account_hash}.json"
        )

    def _load_token_cache(self) -> None:
        """Load token from disk cache if available and still valid.
        Must be called from an executor thread, not the event loop."""
        try:
            with open(self._cache_path) as f:
                data = json.load(f)
            token = data.get("token")
            exp = data.get("exp", 0)
            if token and time.time() < (exp - 60):
                self._token = token
                self._token_exp = exp
                _LOGGER.debug("Loaded valid token from disk cache")
        except Exception:
            pass
        finally:
            self._cache_loaded = True

    def _save_token_cache(self) -> None:
        """Save current token to disk cache.
        Must be called from an executor thread, not the event loop."""
        try:
            with open(self._cache_path, "w") as f:
                json.dump({"token": self._token, "exp": self._token_exp}, f)
            os.chmod(self._cache_path, 0o600)
            _LOGGER.debug("Token saved to disk cache")
        except Exception as e:
            _LOGGER.warning("Could not save token cache: %s", e)

    def _is_token_valid(self) -> bool:
        """Return True if the cached token is still valid."""
        return bool(self._token) and time.time() < (self._token_exp - 60)

    def get_token(self) -> str:
        """Return a valid token, refreshing if necessary.
        Runs in executor thread — disk I/O is safe here."""
        if not self._cache_loaded:
            self._load_token_cache()

        if not self._is_token_valid():
            # Serialize refreshes: the three coordinators can all land here
            # at once with an expired token. Only the first thread through
            # the lock should actually log in; the rest just wait and reuse
            # the token it fetched.
            with self._state.refresh_lock:
                if not self._is_token_valid():
                    self._login()

        return self._token

    def _backoff(self, minimum: float = 0) -> float:
        """Start the wait before the next login and return its length."""
        state = self._state
        delay = max(
            minimum,
            LOGIN_BACKOFF[min(state.login_failures, len(LOGIN_BACKOFF) - 1)],
        )
        state.login_failures += 1
        state.next_login_at = time.monotonic() + delay
        return delay

    def _login(self) -> None:
        """Log in once, unless the credentials were refused or a backoff runs.

        A login-page response only counts as refused credentials after
        REJECTIONS_TO_REAUTH consecutive ones, each at least
        REJECTION_RETRY_DELAY after the previous. Before that it raises
        RainBirdAuthSuspect, which callers treat as a transient failure.
        Only a successful login resets the count: a WAF challenge or a
        network error in between is not evidence either way.

        Caller holds the state's refresh_lock.
        """
        state = self._state
        if state.rejected is not None:
            raise state.rejected
        wait = state.next_login_at - time.monotonic()
        if wait > 0:
            raise RainBirdLoginBackoff(
                f"Login paused for {int(wait)}s after a failed attempt"
            )

        _LOGGER.debug("Fetching new Rain Bird token (channel=%s)", self._channel)
        try:
            if self._channel == AUTH_CHANNEL_APP:
                token = fetch_token_isapp(self._username, self._password)
            else:
                token = fetch_token(self._username, self._password)
        except RainBirdAuthRejected as err:
            state.rejections += 1
            # Never add the exception message or the response body here:
            # status, path and error_text are the parts built to be logged.
            _LOGGER.warning(
                "Rain Bird returned the login page instead of a token "
                "(%d/%d, HTTP %s, %s, page error: %s)",
                state.rejections,
                REJECTIONS_TO_REAUTH,
                err.status,
                err.path or "no path",
                err.error_text or "no error text on the page",
            )
            if state.rejections >= REJECTIONS_TO_REAUTH:
                state.rejected = err
                _LOGGER.warning(
                    "Rain Bird rejected the stored credentials; no further "
                    "logins will be attempted until they are updated"
                )
                raise
            delay = self._backoff(minimum=REJECTION_RETRY_DELAY)
            raise RainBirdAuthSuspect(
                f"Rain Bird returned the login page instead of a token; "
                f"trying again in {delay}s before asking for the password"
            ) from err
        except Exception:
            delay = self._backoff()
            _LOGGER.debug("Login failed; next attempt in %ss", delay)
            raise

        state.reset()
        self._token = token
        self._token_exp = _decode_jwt_exp(token)
        self._save_token_cache()

    def invalidate(self) -> None:
        """Force token refresh on next call."""
        self._token = None
        self._token_exp = 0

    def get_headers(self) -> dict:
        """Return authorization headers for API requests."""
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Accept": "application/json",
        }
