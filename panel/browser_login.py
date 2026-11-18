"""Browser OAuth login: get a fresh site session through an IdP.

Used for accounts the protocol path cannot log in by itself — OAuth-only
identities on forks that refuse to set a password (see ADR-0009). On a
`login_bonus` site the login *is* the check-in, so this runs once per day for
those accounts; everywhere else it runs once, to mint the first session.

Requires the cloakbrowser helpers vendored in `panel/vendor/utils/` — see the
README there for what they are and what was changed.
"""
import asyncio
import json
import math
import os
import re
import shutil
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from panel.vendor.utils.browser import (
	launch_login_context,
	load_browser_login_settings,
	login_with_email_form,
	prepare_browser_page,
	wait_for_waf_ready,
)
from panel.vendor.utils.popups import dismiss_popups

from panel import newapi


@dataclass
class BrowserLogin:
	"""What one browser hop won: the credential to store and who it belongs to."""

	credential: str  # empty when the successful login returned only a body token
	user: dict
	access_token: Optional[str] = None  # Authorization value won by this hop only


@dataclass
class BrowserVisit:
	"""What one visit to a receipt-less site saw.

	`before` is read with the site's own check-in held back, so unlike every earlier
	version of this it is a genuine pre-bonus balance; `receipt` is what the check-in
	route answered. Together they can price a bonus on a site whose quota log never
	mentions one (ADR-0012).
	"""

	before: Optional[dict]
	after: Optional[dict]
	session: Optional[str]
	checkin_at: Optional[float]  # ledger: 0.0 = never, None = cannot say
	checkin_path: Optional[str] = None  # the route that answered, if any
	receipt: Optional[dict] = None  # its response body
	held: bool = False  # was the SPA's automatic check-in actually held back?

	@property
	def refused(self) -> bool:
		"""The route answered, and said no. Not the same as never having asked."""
		return isinstance(self.receipt, dict) and not self.receipt.get('success')

	@property
	def message(self) -> str:
		"""Whatever the route said, for a panel the owner has to debug from.
		relay8 answers `{"message": "", "success": true}` — so often nothing."""
		if not isinstance(self.receipt, dict):
			return ''
		message = self.receipt.get('message') or self.receipt.get('error') or ''
		if isinstance(message, dict):  # OpenAI-shaped errors, same as newapi._fail
			message = message.get('message') or ''
		return str(message).strip()

PROVIDER_BUTTONS = {
	'linuxdo': ('LINUX DO', 'LinuxDO', 'LINUX.DO', 'Linux'),
	'github': ('GitHub', 'Github', 'GITHUB'),
}
CONSENT_TEXTS = ('允许', 'Allow', 'Authorize', 'Continue')
CONSENT_BOXES = ('[role=checkbox][aria-checked="false"]', 'input[type=checkbox]:not(:checked)')
EMAIL_LOGIN_TEXTS = ('邮箱或用户名', '邮箱登录', '使用邮箱', '用户名登录', 'Email')
TURNSTILE_PAGES = ('/profile', '/login')  # routes of these SPAs that load turnstile's api.js
# Cloudflare's own challenge cookies, by **name**. The set is intentionally narrow and scoped to
# the IdP hosts. A small controlled comparison once suggested stale state mattered, but later samples
# did not establish that cause; `_clear_cloudflare_state` is retained as harmless cleanup, not a fix.
CLOUDFLARE_COOKIES = ('cf_clearance', 'cf_chl_rc_ni', '__cf_bm')
CLOUDFLARE_COOKIE_PREFIX = 'cf_chl_'  # the family `cf_chl_rc_ni` belongs to
# Unattended: redirects, consent clicks, and a bounded number of challenge navigations.
#
# Measurements rejected waiting forever on one navigation: single-navigation waits cleared 1/6,
# while re-navigating the same IdP tab cleared 3/4 in the larger sample. The cadence is not proven
# optimal; ~120s is the better-supported choice of the measured options. Re-navigation improves the
# odds but is not a Cloudflare bypass and cannot guarantee a login.
IDP_CHALLENGE_ATTEMPT_S = 120
IDP_CHALLENGE_MAX_ATTEMPTS = 3  # per challenged page, not per run — the hop is a chain
# Sized for the measured *chain*, not one page. Measured 2026-09-14: the hop challenges twice
# (`connect.linux.do/oauth2/authorize` → … → `linux.do/session/sso_provider`), and the clearing
# shape is a second navigation at the 120s cadence. Two pages × two navigations × 120s ≈ 480s,
# plus navigation and consent. A single-page budget is what starved the second challenge live.
# Still a hard deadline: a chain that survives it fails honestly rather than hanging.
SESSION_TIMEOUT_S = 600
HUMAN_TIMEOUT_S = 300  # visible window: someone is typing a password and a 2FA code
INJECTION_VERIFY_TIMEOUT_S = 180  # imported cookies are retained even if this shorter proof times out
INJECTION_TIMEOUT_S = 240  # launch + cookie write + verification; safe close may take longer
POLL_S = 2
HUMAN_AFTER_TICKS = 5  # ~10s of redirects is plenty; after that a login page means a human is needed
# ~30s with no page moving at all. An OAuth hop is a chain of navigations, and consent
# gets clicked every tick, so a stopped IdP tab is a challenge or a form, not progress.
#
# A challenge that is visibly *present* and working no longer counts as this at all — the poll
# loop lets `_challenge_present` hold the counter back for it, because a managed challenge moves
# nothing for minutes and does clear on its own. This counter is now only for a tab that is
# neither moving nor challenged.
STUCK_AFTER_TICKS = 15
# How an IdP tab announces it wants credentials. `/oauth2/authorize` is deliberately not
# here: that is also what a consent page looks like, and clicking one is this loop's job.
IDP_LOGIN_MARKS = ('/login', '/signin', '/sign_in', '/sessions/new', '/u/login')
# Where these forks put their login card, in the order to try. `/login` first because it is what
# most of them serve (and they redirect on to the second when they do not) — measured 2026-09-14
# across every saved OAuth site: five land on `/sign-in` after a redirect, **relay9 stays
# on `/login` with its button present**, and **relay12 stays on `/login` with no button at
# all** while `/sign-in` has it. That middle case is why the second path is a *fallback* rather
# than a replacement: swapping one hardcoded guess for the other would have broken agentrouter.
LOGIN_PATHS = ('/login', '/sign-in')
# How long each route gets to prove it is the right one. Short: this decides *where* to be, and
# the caller's readiness loop does the waiting afterwards. Long enough for a client-rendered card.
LOGIN_PROBE_MS = 3_000
# What Cloudflare's interstitial puts into the document it serves. The frame comes later
# (~6s measured), so the document is the earlier of the two signatures and the one that is
# still there while the challenge is doing nothing visible.
INTERSTITIAL_MARK = 'cdn-cgi/challenge-platform'
# A tab that has already been *authorized* and is carrying the assertion home. Measured live
# 2026-09-14: the run reached
# `connect.linux.do/discourse/sso_callback?sso=<base64 assertion>` — a completed LinuxDO
# authorization carrying `external_id`, `username`, `groups` and `nonce` — and the poll loop
# re-navigated it to the authorize URL, because `_challenge_present` still read a challenge
# signature on that host and nothing excluded the callback. That threw a won authorization away
# and redid the whole hop. `/oauth2/authorize` is deliberately absent: clicking it is the loop's
# job. Note `sso_provider` is NOT here — it is an intermediate page in the same measured chain
# (`authorize` → `session/sso_provider` → `discourse/sso_callback`) and may itself be challenged.
IDP_CALLBACK_MARKS = ('/sso_callback', '/discourse/sso')
BUTTON_TIMEOUT_MS = 20_000  # SPA render + however long Turnstile keeps the button disabled
# One click attempt, retried until BUTTON_TIMEOUT_MS runs out rather than spent in one go: what
# gets in the way here arrives *after* the button does, so a single long wait cannot recover from
# it while a short one plus a dismissal can. Measured 2.7s for the click that lands.
CLICK_TRY_MS = 5_000
CONSENT_TIMEOUT_MS = 2_000  # a consent page is already open; do not stall the poll loop
TURNSTILE_CLICK_TIMEOUT_MS = 1_000  # optional work inside an already bounded poll loop
TURNSTILE_TIMEOUT_S = 20
UNSAFE_IN_A_PATH = re.compile(r'[^0-9A-Za-z._-]+')


def profile_name(account_name: str) -> str:
	"""The directory name this account's browser profile gets.

	One function rather than the four copies of this line it replaces, because deleting a
	profile has to land on exactly the path launching one created. Two names that differ
	only in a character this strips share a directory — deliberate, and why `store` keys
	accounts by (name, base_url): renaming the rule would orphan every existing profile.
	"""
	return UNSAFE_IN_A_PATH.sub('_', account_name).strip('._') or 'account'


def profile_dir(account_name: str, provider: str) -> Path:
	"""Where this account's profile lives, asked of the same code that launches it.

	Reading `load_browser_login_settings` rather than rebuilding the path keeps the answer
	true if the layout or `CHECKIN_BROWSER_PROFILE_DIR` ever moves.
	"""
	return load_browser_login_settings(profile_name(account_name), provider).profile_dir


def forget_profile(account_name: str, provider: str) -> bool:
	"""Delete this account's browser profile. True if there was one.

	What goes with it is the IdP session, which is the point: an account deleted from the
	database still had its whole github.com or linux.do login sitting in here, and no panel
	screen mentioned the directory. There is no undo — the session has to be pasted or
	logged in again — so the caller asks first.

	The containment check is belt and braces. `profile_name` already strips every path
	separator, so no account name can reach outside the root; the check is what makes that
	still true if the rule is ever loosened, because the operation on the other side of it
	is `rmtree`.
	"""
	target = profile_dir(account_name, provider).resolve()
	root = Path(os.getenv('CHECKIN_BROWSER_PROFILE_DIR', '.browser_profiles')).resolve()
	if root not in target.parents:
		raise ValueError(f'{target} 不在 profile 根目录 {root} 之下，拒绝删除')
	if not target.is_dir():
		return False
	shutil.rmtree(target)
	return True


def _idp_pages(context, root: str) -> list:
	"""The tabs that are at the IdP rather than at the site (and not blank)."""
	return [p for p in context.pages if root not in p.url and p.url not in ('', 'about:blank')]


def _idp_wants_a_human(context, root: str) -> bool:
	"""True while some IdP tab is parked on a login page (github.com/login,
	linux.do/login, ...) — i.e. the IdP session in this profile has expired."""
	return any(mark in p.url for p in _idp_pages(context, root) for mark in IDP_LOGIN_MARKS)


def _why_a_human_is_needed(
	context, root: str, tick: int, still: int, progress: bool = False
) -> Optional[str]:
	"""Why a headless run cannot finish on its own, or None while it still might.

	Three shapes, because a page that wants hands does not always say so. A login *page*
	names itself, and ~10s of redirects is plenty before believing one. But
	`connect.linux.do` renders whatever it wants at `/oauth2/authorize` — measured:
	Cloudflare answers that URL with a `Just a moment...` challenge — so the tab sits on an
	authorize URL that looks exactly like a consent page we are about to click. Nothing
	there matches `/login`, so a URL check never fires and the run burns the full 120s to
	reach a TimeoutError that names no cause.

	`progress` is a checkbox click this tick, and it only ever excuses the *stall* shapes.
	It must never excuse the first one: the IdP's own login page means the session in this
	profile is gone, and no amount of clicking renews it. Measured 2026-09-14 on grok-heavy
	(the whole failure): the OAuth hop bounced `linux.do/session/sso_provider` →
	`linux.do/login`, that login page rendered its own Turnstile widget, `_click_turnstile`
	found and clicked its checkbox, and the resulting `progress` suppressed this verdict
	every tick — so a run that could have said 「需要先人工登录一次」 in 10s instead spent the
	full 600s and reported 页面一直在动, which was also untrue.

	So the second shape is simply **nothing moving**: no page changed URL for ~30s. A
	consent page does not do that — we click it every tick and it navigates. Only a
	challenge or a form waiting for hands does.

	Not a challenge, though: the poll loop lets a *present* one hold this counter back
	(`_challenge_present`), because a managed challenge stops everything for minutes and
	then clears on its own. What reaches here as "nothing moving" is the tab with neither
	movement nor a challenge on it — and the deadline, not this check, is what ends a
	challenge that never clears.

	The third is the same stall on the *site's own* pages, and it is a separate branch
	because `_idp_pages` excludes them by construction: it keeps the tabs whose URL does
	not contain `root`. A challenge served by the check-in site itself therefore left the
	stall detector with an empty list and reported nothing (measured on relay14: the
	whole 120s spent, then a bare timeout). Which side stalled changes the advice, so the
	two branches say different things; the site's own challenge is worth another go, and
	the run's own bounded retry now issues one.
	"""
	if tick >= HUMAN_AFTER_TICKS and _idp_wants_a_human(context, root):
		return 'IdP 显示的是它自己的登录页'
	if progress:
		# A checkbox click is browser progress, but only for the shapes it can actually be
		# progress *on*. The IdP login page above is decided before this and stays decided.
		return None
	if still >= STUCK_AFTER_TICKS and _idp_pages(context, root):
		urls = ' | '.join(p.url for p in _idp_pages(context, root))
		return f'IdP 页面卡住不动（多半是 Cloudflare 人机验证）: {urls}'
	# Blank tabs are excluded for the same reason `_idp_pages` excludes them: `about:blank`
	# is what the context opens with, and a run that has not navigated yet is not stuck.
	parked = [p.url for p in context.pages if p.url not in ('', 'about:blank')]
	if still >= STUCK_AFTER_TICKS and parked:
		return f'站点自己的页面卡住不动（多半是 Cloudflare 人机验证）: {" | ".join(parked)}'
	return None


def _root(base_url: str) -> str:
	host = base_url.split('://', 1)[-1].split('/')[0]
	return '.'.join(host.split('.')[-2:])


def _selectors(texts) -> tuple[str, ...]:
	return tuple(f'{tag}:has-text("{t}")' for t in texts for tag in ('button', 'a'))


async def _unblock_login(page, texts, timeout_ms: int = BUTTON_TIMEOUT_MS) -> None:
	"""Get one of `texts` into a clickable state, or give up quietly.

	Covers the four ways a login page is not ready. It is still empty at `domcontentloaded`
	(4.6s on relay10). Its buttons stay `disabled` until 「我已阅读并同意用户协议」 is ticked
	— a box that can render a beat *after* the button does, so one pass at ticking it loses
	the race about half the time. And something can be drawn *over* the button: relay8
	opens with a 系统公告 modal (`.semi-modal-wrap`, `position: fixed`, `z-index: 1000`) whose
	body paragraph lands across the OAuth buttons, which is what `dismiss_popups` is for.

	Ready therefore means "receives events", not `is_enabled()`. A covered button *is*
	enabled, so the old check returned in 0.0s while the page was still a skeleton and the
	modal had yet to render; the click then spent its full 20s failing the same hit test
	Playwright performs, and reported it as the button not being there at all.

	And **twice in a row**, half a second apart, because one look is satisfied by the moment
	before the page has finished happening. Measured on relay8: at t=0.0 the buttons
	are drawn over a Semi skeleton and nothing is over them, at t=0.5 the 公告 modal is up.
	A single look returns in that first instant and the click lands on a button whose handler
	cannot do anything yet — the card is still waiting for the site status `_forget_spa_login`
	cleared, so it has no OAuth URL to go to. That click *succeeds* mechanically and the run
	then dies 30s later in the poll loop, reporting a stall on a page it never left. Two
	consecutive looks cost half a second on a page that was ready all along.

	The fourth is a Cloudflare challenge **on this page**, one the button never becomes
	clickable behind. `_click_turnstile` was only ever called from inside the poll loop,
	which is reached after a button click has already succeeded — so on a site serving the
	challenge on its own `/sign-in` the preparation burned its whole budget and reported
	「找不到登录入口」 for a login the page plainly had (relay13). Asking
	every pass costs nothing when there is no challenge, and frames are re-resolved rather
	than cached, because the widget replaces its iframe while changing modes.
	"""
	deadline = time.monotonic() + timeout_ms / 1000
	steady = 0
	while time.monotonic() < deadline:
		await _click_turnstile(page)  # progress only: it never counts as readiness or a login
		if await _receives_clicks(page, texts):
			steady += 1
			if steady >= 2:
				return
		else:
			steady = 0
			await _accept_terms(page)
			await dismiss_popups(page)
		await asyncio.sleep(0.5)


async def _receives_clicks(page, texts) -> bool:
	"""Whether one of `texts` is drawn, enabled, and owns its own centre point.

	That last clause is the question Playwright's click asks before it will act, and the one
	nothing else here was asking: `elementFromPoint` at the middle of the button has to come
	back as the button or something inside it. Anything else is a layer in the way.
	"""
	button = page.locator(', '.join(_selectors(texts))).first
	try:
		if not await button.is_enabled(timeout=1000):
			return False
		return bool(await button.evaluate("""(el) => {
			const r = el.getBoundingClientRect();
			if (r.width === 0 || r.height === 0) return false;
			const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
			return at === el || el.contains(at);
		}"""))
	except Exception:  # not drawn yet, or it went away between the two calls
		return False


async def _accept_terms(page) -> None:
	"""Tick every visible unticked box on the page — on a login form that is the terms
	box and nothing else worth leaving alone.

	`check()` rather than `click()`: it waits for the element to stop moving (a freshly
	hydrated SPA is still settling) and then verifies the box really is checked, which a
	click cannot promise.
	"""
	for selector in CONSENT_BOXES:
		boxes = page.locator(selector)
		for index in range(await boxes.count()):
			box = boxes.nth(index)
			try:
				if await box.is_visible():
					await box.check(timeout=2000)
			except Exception:  # a hidden mirror input, or it vanished on the first check
				continue


async def _click_turnstile(page) -> bool:
	"""Click the current checkbox in a Cloudflare challenge frame, if there is one.

	The widget replaces its frame while changing challenge modes, so frames and locators
	are resolved on every call. Absence and replacement are normal: both flows calling
	this helper already own the deadline and will ask again on their next poll.
	"""
	for frame in getattr(page, 'frames', ()):
		try:
			if urlsplit(frame.url).hostname != 'challenges.cloudflare.com':
				continue
			checkbox = frame.get_by_role('checkbox', checked=False).first
			if not await checkbox.is_visible():
				continue
			await checkbox.click(timeout=TURNSTILE_CLICK_TIMEOUT_MS)
			return True
		except Exception:  # the optional frame disappeared or was replaced between calls
			continue
	return False


def _has_turnstile(page) -> bool:
	"""Is a Cloudflare challenge frame on this page right now?

	Only ever asked to *name* a failure, never to decide one: presence is not proof that
	Cloudflare will or will not issue anything, and a click on it is browser progress rather
	than a login (trap 5).

	A frame whose handle has already died has no URL to read and raises; that only decides
	which wording is used, so it must not turn a written failure into a traceback.
	"""
	hosts = []
	for frame in getattr(page, 'frames', ()):
		try:
			hosts.append(urlsplit(frame.url).hostname)
		except Exception:
			continue
	return 'challenges.cloudflare.com' in hosts


async def _challenge_present(page) -> bool:
	"""Is a Cloudflare challenge on this page right now, working or waiting on us?

	Asked once per poll tick to tell a *wait* from a *stall*, which is not a question the URL
	can answer: `connect.linux.do/oauth2/authorize` sits unchanged for the whole of a managed
	challenge. The signature is either the challenge's own frame or the interstitial script it
	injects into the document, and both arrive with the challenge and leave with it — measured
	2026-09-13, the frame appears ~6s after the interstitial and `window.turnstile` is already
	defined when it does.

	Presence is never evidence: it buys waiting time and nothing else. It must not reach
	`_logged_in`, a credential, `checked_in`, or any outcome — a challenge that clears is a
	*different page*, and what is on that page is what decides.

	`_has_turnstile` already answers the frame half, re-resolving frames per call (the widget
	replaces its iframe while changing modes) and swallowing a dead handle rather than throwing
	out of the poll loop. The document is the earlier half of the signature, and an unavailable
	one reads as "no challenge" for the same reason.
	"""
	try:
		document = await page.content()
	except Exception:  # no content, or a page mid-navigation — a fake has neither
		document = ''
	return INTERSTITIAL_MARK in str(document) or _has_turnstile(page)


async def _wait_for_rendered(page, texts, timeout_ms: int = BUTTON_TIMEOUT_MS) -> None:
	"""Wait for one of `texts` to be drawn. An SPA login page is still empty at
	`domcontentloaded` — 4.6s on relay10 — and `is_visible()` does not wait, so
	looking once concluded the OAuth button did not exist before it was ever drawn."""
	try:
		await page.locator(', '.join(_selectors(texts))).first.wait_for(state='visible', timeout=timeout_ms)
	except Exception:
		pass


async def _click_first(page, texts, timeout_ms: int = BUTTON_TIMEOUT_MS) -> bool:
	"""Click the first of `texts` that is there, in priority order (buttons before links).

	Playwright's click waits for the element to become enabled on its own, which covers
	a button that is still disabled when we get to it.

	Short tries in a loop rather than one long wait, because the thing in the way arrives
	*after* the button: relay8's 系统公告 modal renders ~0.5s behind the login card, so
	a click that began on a clear button is still waiting when the modal lands on top, and
	Playwright's retries can never pass the hit test again. Each pass therefore gives up
	early, clears whatever is over the page, and looks again — measured: the click lands in
	2.7s once the modal is gone. Two selectors matching at 20s each also spent 41s reaching
	the same failure, and this loop has to fit inside the poll loop's own budget.
	"""
	await _wait_for_rendered(page, texts, timeout_ms)
	deadline = time.monotonic() + timeout_ms / 1000
	# Never longer than the whole budget: the consent page is called with 2s precisely so it
	# cannot stall the poll loop, and a 5s try per selector would spend 40s of it.
	try_ms = min(CLICK_TRY_MS, timeout_ms)
	while True:
		for selector in _selectors(texts):
			try:
				button = page.locator(selector).first
				if await button.is_visible():
					await button.click(timeout=try_ms)
					return True
			except Exception:
				continue
		if time.monotonic() >= deadline:
			return False
		await dismiss_popups(page)
		await _accept_terms(page)
		await asyncio.sleep(0.5)


async def _why_no_button(page, texts, provider: str) -> str:
	"""Why `_click_first` came back False, in the owner's words.

	Three causes, and they need different words because they need different fixes. A site
	that really has no such login. A button that is there but under something — reported as
	「找不到登录入口」 for a page whose LinuxDO button was drawn, enabled, and 40px from the
	pointer, which sent the owner looking for a login method the site plainly had. And a
	Cloudflare prompt holding the login card back, where the fix is a retry rather than
	either of the other two answers (relay13 — see `_unblock_login`).
	"""
	drawn = False
	try:
		drawn = await page.locator(', '.join(_selectors(texts))).first.is_visible()
	except Exception:
		drawn = False
	if not drawn:
		if _has_turnstile(page):
			# Not the site's absence: measured on relay13, the page served a
			# Cloudflare challenge before the LinuxDO button was actionable, so both looks were
			# spent behind it. Saying 找不到 sends the owner to find a login method it has.
			return (
				f'{page.url} 上有 Cloudflare 人机验证挡在登录按钮前面，两次都没等到它放行。'
				'直接再试一次通常就能过（这一次挣到的验证凭据已经留在 profile 里）；'
				'连着几次都这样，再点「浏览器登录」开可见窗口看一眼'
			)
		return f'{page.url} 上找不到 {provider} 登录入口（重新载入后再找过一次）'
	return (
		f'{provider} 登录按钮在 {page.url} 上，但一直点不到 —— 有东西盖在它上面（站点公告弹窗之类），'
		'关不掉。直接再试一次通常就好；连着几次都这样，再点「浏览器登录」开可见窗口手动点一下'
	)


async def _spa_user(context, root: str) -> Optional[dict]:
	"""The user object the New API SPA writes to localStorage after a login.

	It carries the id the site wants back as the `new-api-user` header, the username
	and the current quota — everything an authenticated read would have told us, from
	a page that is already authenticated. Some sites now put a WAF CAPTCHA in front of
	`/api/user/self`, which no cookie gets past, so this is not a shortcut but the
	only reading available (ADR-0010).
	"""
	for page in context.pages:
		if root not in page.url:
			continue
		try:
			user = await page.evaluate('() => JSON.parse(localStorage.getItem("user") || "null")')
		except Exception:  # not on the site yet, or a WAF interstitial
			continue
		if isinstance(user, dict) and user.get('id'):
			return user
	return None


def _cookies_named(cookies, name: str, root: str) -> list[str]:
	return [c['value'] for c in cookies if c.get('name') == name and root in (c.get('domain') or '') and c.get('value')]


async def _site_user_anywhere(context, root: str, api_user=None) -> Optional[dict]:
	"""`/api/user/self` read from whichever open page is on the site.

	The page is behind the WAF's JS challenge already, so this returns the *current*
	balance where httpx only gets a challenge (ADR-0010) — and unlike the SPA's stored
	login response it is never quota=0.
	"""
	for page in context.pages:
		if root not in page.url:
			continue
		user = await _site_user(page, api_user)
		if user:
			return user
	return None


async def _logged_in(context, base_url: str, root: str) -> Optional[tuple[str, dict]]:
	"""(the credential worth keeping, the user) once this run has really logged in.

	Three proofs, because forks differ in what they even set. `GET /api/user/self` is
	the strongest and says *which* session cookie is live — a `session` cookie proves
	nothing by itself, New API keeps the pre-login OAuth state in one. A JWT fork
	(relay10) sets no cookie at all until a login succeeds, so its `new_api_refresh`
	appearing after `_forget_site` cleared it is proof in itself — and it must be handed
	over *unspent*, because exchanging it invalidates it and the check-in needs it. When
	a WAF answers the API instead of the site, the SPA's own localStorage stands in: we
	emptied it before clicking the button, so a user in it means *this* login worked
	(ADR-0010).
	"""
	user = await _spa_user(context, root)
	api_user = user.get('id') if user else None
	cookies = await context.cookies()
	sessions = _cookies_named(cookies, 'session', root)
	for value in sessions:
		confirmed = await newapi.whoami(base_url, session=value, api_user=api_user)
		if confirmed:
			return value, confirmed
	for value in _cookies_named(cookies, newapi.REFRESH_COOKIE, root):
		return value, user or {}
	fresh = await _site_user_anywhere(context, root, api_user)  # a WAF'd API still answers in-page
	if fresh and sessions:
		return max(sessions, key=len), fresh
	# ponytail: longest wins. Without the API we cannot ask which cookie is live, and a
	# logged-in New API session carries the user payload, so it is longer than the
	# pre-login state cookie (668 vs 400 chars on agentrouter). Revisit if a fork
	# starts issuing same-length cookies for both.
	return (max(sessions, key=len), user) if sessions and user else None


async def _forget_site(context, root: str) -> list[dict]:
	"""Log out of the site while staying logged in at the IdP. Returns what it dropped.

	Sites that grant the daily bonus on login show no OAuth button while a
	session is live, and reusing that session would credit nothing — so drop the
	site's cookies and keep everyone else's. This is the "logout then re-login"
	those sites require, minus the logout button.

	The dropped cookies come back so the caller can put them *back* when the re-login
	does not land. This is not tidiness: the same clear costs two kinds of site
	opposite amounts. A `login_bonus` site has to be logged out or it credits nothing,
	while on a `visit` site the session **is** the check-in — measured on relay8,
	one card minted by an OAuth hop carried 13 days of daily runs on its own, and no
	daily run ever mints another. So a clear followed by a failed login turns "collecting
	every day" into "cannot log in at all", and the owner is worse off for having pressed
	the button. Nothing here can tell the two sites apart (this function is handed a
	`base_url`, never a mechanism), so it does not try: it hands the evidence back and
	`browser_login` rolls forward on success, back on failure.
	"""
	cookies = await context.cookies()
	dropped = [c for c in cookies if root in (c.get('domain') or '')]
	keep = [c for c in cookies if root not in (c.get('domain') or '')]
	await context.clear_cookies()
	if keep:
		await context.add_cookies(keep)
	return dropped


def _is_cloudflare_cookie(cookie: dict, hosts: tuple[str, ...]) -> bool:
	"""Is this a stale Cloudflare challenge cookie for one of `hosts`?

	Reads the **name** and the **domain** and nothing else — no value is looked at, returned or
	logged, so there is nothing here for a `cf_clearance` or a session to leak through.
	"""
	name = str(cookie.get('name') or '')
	if name not in CLOUDFLARE_COOKIES and not name.startswith(CLOUDFLARE_COOKIE_PREFIX):
		return False
	return _domain_under_any(cookie.get('domain'), hosts)


def _domain_under_any(domain, hosts: tuple[str, ...]) -> bool:
	"""Playwright reports `Domain=.linux.do` with the leading dot; hosts here never carry one."""
	domain = str(domain or '').lstrip('.')
	return bool(domain) and any(domain == h or domain.endswith('.' + h) for h in hosts)


async def _clear_cloudflare_state(context, hosts: tuple[str, ...]) -> int:
	"""Drop stale Cloudflare challenge cookies for `hosts`. Returns how many.

	A controlled comparison once suggested that a persistent profile's Cloudflare state blocked
	this IdP hop, but the result did not repeat reliably: fresh and persistent profiles both
	failed in later samples. The causal claim is therefore withdrawn. This small, scoped cleanup
	is retained because it is harmless, leaves the IdP session and site credential alone, and may
	remove stale challenge state; it is not load-bearing for the bounded re-navigation retry.

	What it must never touch is the thing being used: the IdP *session* (`.linux.do`'s `_t`,
	`g_state`) is the identity the hop spends, and the site's credential (`session`,
	`new_api_refresh`) is the run's whole product. Neither is in the Cloudflare set, and the
	domain scope keeps an unrelated site's clearance out of it as well.

	The jar goes back wholesale rather than one `clear_cookies(domain=…)` per host, because
	Playwright's name/domain filters are **regexes** and a domain's dots are not literals in one
	— so the selection is done here, on names and hosts, and the rewrite is not filtered at all.
	"""
	cookies = await context.cookies()
	stale = {id(c) for c in cookies if _is_cloudflare_cookie(c, hosts)}
	if not stale:
		return 0
	keep = [c for c in cookies if id(c) not in stale]
	await context.clear_cookies()
	if keep:
		await context.add_cookies(keep)
	return len(stale)


async def _forget_spa_login(page, base_url: str, texts=None) -> None:
	"""Cookies are only half of the logout: the SPA keeps the user in localStorage
	and its router sends /login straight to /console while that is there, so the
	OAuth button we came for would not exist. Clear it and come back.

	Everything goes, not just the keys that look like a login. Which key holds the user
	differs by fork, and a logout that misses it leaves us on /console with no button —
	the failure this function exists to prevent. The cost is that the site's cached status
	goes too, which can cost the login card its provider chooser on the next paint; the
	caller reloads once when the button is missing rather than narrowing the clear here.
	"""
	try:
		await page.evaluate('() => { localStorage.clear(); sessionStorage.clear(); }')
	except Exception:  # nothing stored yet — a WAF interstitial has no site origin
		return
	# `texts` is only absent for a caller that is not looking for a login entry point; fall back
	# to the plain first route there rather than probing for something it does not want.
	if texts:
		await _goto_login(page, base_url, texts)
	else:
		await page.goto(f'{base_url}{LOGIN_PATHS[0]}', wait_until='domcontentloaded')


async def _goto_login(page, base_url: str, texts, timeout_ms: int = LOGIN_PROBE_MS) -> None:
	"""Land on the site's own login page, trying each route in `LOGIN_PATHS` until one draws `texts`.

	Not every fork redirects `/login` to its real login route. Measured 2026-09-14 across every
	saved OAuth site: five redirect `/login` → `/sign-in`, relay9 serves its login card
	*at* `/login`, and **relay12 serves a page with no login entry point at `/login`** while
	`/sign-in` has it — which is the whole defect, reported as 「找不到 linuxdo 登录入口」 for a site
	whose button was one path away.

	The probe is short on purpose (`LOGIN_PROBE_MS`): this answers *which route*, not whether the
	page is ready. Readiness stays with the caller, whose `_unblock_login` owns the real wait — and
	whose reload-once-then-retry still has to work, which is why this only ever moves forward to the
	next route and never re-tries the first.

	On a site that redirects, the first route is already the second page, so the button shows up
	immediately and no extra navigation happens. When no route draws it the last one is left in
	place, so the caller's failure names a page the owner could actually open.
	"""
	for path in LOGIN_PATHS:
		await page.goto(f'{base_url}{path}', wait_until='domcontentloaded')
		await _wait_for_rendered(page, texts, timeout_ms)
		try:
			if await page.locator(', '.join(_selectors(texts))).first.is_visible():
				return
		except Exception:  # an unhydrated page has no such locator yet
			continue


# Cloudflare's own widget script — what a fork loads when it wants a token. Loaded explicitly
# only when the page has not (see `MINT_TURNSTILE_JS`).
TURNSTILE_API_URL = (
	'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
)

MINT_TURNSTILE_JS = """async ([sitekey, apiUrl]) => {
	const wait = (ms) => new Promise(r => setTimeout(r, ms));
	// api.js is loaded async by the page, so window.turnstile shows up late — rendering the
	// moment the DOM is ready is how relay15 produced no token at all.
	for (let i = 0; i < 40 && typeof window.turnstile !== 'object'; i++) await wait(250);
	if (typeof window.turnstile !== 'object' && apiUrl) {
		// Some forks enforce a token on their check-in route while never loading api.js
		// themselves, so there is nothing to render into. Measured 2026-09-14 on
		// relay12: no `turnstile` request, no `api.js` in the document, the sitekey
		// absent from the page, and `window.turnstile` undefined on every route — yet
		// `GET api.js` from this page and rendering it minted a 752-char token that the
		// check-in route accepted. Loading it here is the same script the site's own widget
		// would load; it only fails behind a CSP that forbids the origin.
		await new Promise((resolve) => {
			const s = document.createElement('script');
			s.src = apiUrl; s.async = true;
			s.onload = resolve; s.onerror = resolve;
			document.head.appendChild(s);
		});
		for (let i = 0; i < 40 && typeof window.turnstile !== 'object'; i++) await wait(250);
	}
	if (typeof window.turnstile !== 'object') return null;
	const box = document.createElement('div');
	box.style.cssText = 'position:fixed;bottom:4px;right:4px;width:300px;height:65px;z-index:99999';
	document.body.appendChild(box);
	try {
		// No turnstile.ready(): it throws when the site loads api.js with async/defer.
		return window.turnstile.render(box, {sitekey});
	} catch (e) { return null; }
}"""

TURNSTILE_RESPONSE_JS = """(widgetId) => {
	try { return window.turnstile.getResponse(widgetId) || null; }
	catch (e) { return null; }
}"""


async def _mint_turnstile(page, base_url: str, sitekey: str) -> Optional[str]:
	"""Get a Turnstile token out of the site's own widget, or None if Cloudflare refuses.

	Some forks reject their check-in route with `Turnstile token 为空` and never render the
	widget themselves in this browser — but the API is loaded (the page ships
	`turnstile/v0/api.js?render=explicit`), so rendering it ourselves can mint a token the
	route accepts: measured 730 chars, and `POST /api/user/checkin?turnstile=…` answered
	`签到成功`. Cloudflare does not always agree to render, and only some routes of the SPA
	load the API at all, so try the pages most likely to have it and take the first token.
	"""
	for path in ('', *TURNSTILE_PAGES):
		if path:
			try:
				await page.goto(f'{base_url}{path}', wait_until='domcontentloaded')
			except Exception:
				continue
		try:
			widget_id = await page.evaluate(MINT_TURNSTILE_JS, [sitekey, TURNSTILE_API_URL])
		except Exception:
			widget_id = None
		if widget_id is None:
			continue
		deadline = time.monotonic() + TURNSTILE_TIMEOUT_S
		while time.monotonic() < deadline:
			try:
				token = await page.evaluate(TURNSTILE_RESPONSE_JS, widget_id)
			except Exception:
				break
			if token:
				return token
			await _click_turnstile(page)
			await asyncio.sleep(0.5)
	return None


async def mint_turnstile(
	*, base_url: str, provider: str, account_name: str, sitekey: str, headless: bool = True
) -> Optional[str]:
	"""Open a browser only to mint a Turnstile token — no login, no logout, no OAuth.

	A check-in that fails for want of a token usually has a perfectly good credential;
	logging in again to get one is both slower and more fragile (the IdP may want a human
	on a new exit IP). The widget does not care whether anyone is signed in, so this
	visits `/login` and renders it there.
	"""
	base_url = base_url.rstrip('/')
	profile = profile_name(account_name)
	# Ephemeral on purpose: there is nothing to remember, and a persistent profile
	# accumulates Cloudflare challenge state that makes the widget refuse to render —
	# measured, a fresh context mints where the account's own profile does not.
	settings = replace(
		load_browser_login_settings(profile, provider, persist_profile=False), headless=headless
	)
	context = await launch_login_context(settings, use_proxy=True)  # the challenge needs the detour
	try:
		page = await context.new_page()
		await prepare_browser_page(page)
		# This one loads the widget rather than a login card, so it must land on a page that
		# actually carries Turnstile. `LOGIN_PATHS` covers `/login` and, when that page has no
		# login entry point at all, `/sign-in` — measured: relay12 serves a card-less page
		# at `/login`. Passing no `texts` keeps this to the plain navigation the widget needs.
		await page.goto(f'{base_url}/login', wait_until='domcontentloaded')
		# /login bounces to /sign-in on these forks, and a navigation part-way through the
		# render tears down the widget's JS context — so let the page settle first.
		try:
			await page.wait_for_load_state('networkidle', timeout=15_000)
		except Exception:
			await asyncio.sleep(2)
		return await _mint_turnstile(page, base_url, sitekey)
	finally:
		await context.close()


SITE_JSON_JS = """async ([path, apiUser]) => {
	try {
		const headers = {Accept: 'application/json'};
		if (apiUser) headers['new-api-user'] = String(apiUser);
		const r = await fetch(path, {headers});
		return JSON.parse(await r.text());
	} catch (e) { return null; }
}"""

SITE_POST_JS = """async ([path, apiUser]) => {
	try {
		const headers = {Accept: 'application/json'};
		if (apiUser) headers['new-api-user'] = String(apiUser);
		const r = await fetch(path, {method: 'POST', headers});
		const text = await r.text();
		try { return JSON.parse(text); } catch (e) { return {success: false, message: text.slice(0, 200)}; }
	} catch (e) { return null; }
}"""

# The route a `visit` site's own SPA posts on mount. relay8's bundle holds
# `async function uD(){const e=await be.post("/api/user/sign_in")...}`, called from the
# router's `useEffect(() => { id > 0 && uD() }, [id])` — so *the page load is the POST*.
VISIT_CHECKIN_PATHS = ('/api/user/sign_in', '/api/user/checkin', '/api/user/check_in')


async def _site_checkin_at(page, api_user=None) -> Optional[float]:
	"""When the site's own quota log last recorded a check-in, read from inside the page.

	Same receipt `newapi.last_checkin_at` fetches over HTTP, for the sites where only a
	browser can reach the API at all. None means "cannot say", never "no".
	"""
	try:
		body = await page.evaluate(SITE_JSON_JS, ['/api/log/self?p=0&page_size=20', api_user])
	except Exception:
		return None
	if not isinstance(body, dict) or not body.get('success'):
		return None
	data = body.get('data')
	items = data.get('items') if isinstance(data, dict) else data
	if not isinstance(items, list):
		return None
	stamps = [
		item.get('created_at')
		for item in items
		if isinstance(item, dict) and newapi.CHECKIN_LOG.search(str(item.get('content') or ''))
	]
	# An empty log is not proof of anything; an entry-carrying log without a check-in is.
	return max((s for s in stamps if isinstance(s, (int, float))), default=0.0) if items else None


async def _hold_check_in(page) -> bool:
	"""Abort the SPA's automatic check-in POST for as long as this route is installed.

	Without this the site collects the bonus during the first authenticated page load and
	the `before` reading taken afterwards already contains it — so the balance never
	appears to move and the run cannot tell 签到成功 from 今日已签到. Aborting costs nothing:
	the bonus is still there to collect, and `_site_check_in` posts it a moment later.
	"""

	async def abort(route):
		try:
			await route.abort()
		except Exception:  # the page navigated out from under it
			pass

	try:
		for path in VISIT_CHECKIN_PATHS:
			await page.route(f'**{path}', abort)
		return True
	except Exception:  # no interception available: fall back to the old, blind behaviour
		return False


async def _release_check_in(page) -> None:
	for path in VISIT_CHECKIN_PATHS:
		try:
			await page.unroute(f'**{path}')
		except Exception:
			continue


async def _site_check_in(page, api_user=None) -> tuple[Optional[str], Optional[dict]]:
	"""POST the site's own check-in route from inside the page. (path, response body).

	This is not an extra action: it is the exact request the SPA fires on mount, and the
	route is idempotent — a second call on a collected day answers without granting
	anything. Doing it explicitly is what makes the bonus *measurable*, because the
	balance either side of this one call is a real before/after (ADR-0012).
	"""
	for path in VISIT_CHECKIN_PATHS:
		body = await page.evaluate(SITE_POST_JS, [path, api_user])
		if isinstance(body, dict) and 'success' in body:
			return path, body
	return None, None


async def _site_user(page, api_user=None) -> Optional[dict]:
	"""`GET /api/user/self` from inside the page.

	The browser has already run the WAF's JS challenge, so this reaches the API that
	httpx only ever gets a challenge page from — and unlike the SPA's stored login
	response, it carries the *current* balance instead of quota=0 (ADR-0012). The
	`new-api-user` header is as mandatory here as anywhere else on these forks.
	"""
	try:
		body = await page.evaluate(SITE_JSON_JS, ['/api/user/self', api_user])
	except Exception:
		return None
	data = body.get('data') if isinstance(body, dict) else None
	return data if isinstance(data, dict) and data.get('id') else None


OPEN_ONLY_JSON_JS = """async ([path, token]) => {
	try {
		const r = await fetch(path, {
			headers: {Accept: 'application/json', Authorization: 'Bearer ' + token},
			credentials: 'include', cache: 'no-store', signal: AbortSignal.timeout(8000)
		});
		return r.ok ? await r.json() : null;
	} catch (e) { return null; }
}"""


async def _open_only_allowance(page, token: Optional[str], user: dict) -> tuple[dict, Optional[float]]:
	"""Keep the SPA alive until its daily allowance is visible; never refresh or claim it ourselves."""
	if not isinstance(token, str) or not token:
		return user, None
	deadline = time.monotonic() + 30
	today = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
	latest = None
	current = user

	async def get(path):
		try:
			return await asyncio.wait_for(
				page.evaluate(OPEN_ONLY_JSON_JS, [path, token]),
				timeout=max(0.1, min(8, deadline - time.monotonic())),
			)
		except Exception:  # keep the rotating credential even if confirmation is unreadable
			return None

	while time.monotonic() < deadline:
		body = await get('/api/log/self?type=1&p=0&page_size=100')
		data = body.get('data') if isinstance(body, dict) and body.get('success') is True else None
		items = data.get('items') if isinstance(data, dict) else data
		if isinstance(items, list):
			stamps = [
				item.get('created_at') for item in items
				if isinstance(item, dict) and item.get('type') == 1
				and re.match(r'^Daily allowance(?:\s|$)', str(item.get('content') or ''), re.I)
			]
			valid = [s for s in stamps if type(s) in (int, float) and math.isfinite(s) and 0 < s <= time.time() + 5]
			if valid:
				latest = max(latest or 0, max(valid))
		# Read after the ledger: the refresh response may predate the grant.
		body = await get('/api/user/self')
		data = body.get('data') if isinstance(body, dict) and body.get('success') is True else None
		if isinstance(data, dict) and data.get('id') == user.get('id'):
			current = data
		if latest is not None and latest >= today:
			break
		remaining = deadline - time.monotonic()
		if remaining <= 0:
			break
		await asyncio.sleep(min(2, remaining))
	return current, latest


async def browser_visit(
	*,
	base_url: str,
	account_name: str,
	provider: str = 'password',
	username: Optional[str] = None,
	password: Optional[str] = None,
	headless: bool = True,
	open_only: bool = False,
	stored_session: Optional[str] = None,
) -> BrowserVisit:
	"""Load the site in a browser that is (or gets) logged in, and collect the bonus.

	Such a site grants the day's bonus from its *own SPA*: relay8's bundle posts
	`/api/user/sign_in` out of the router's mount effect, so merely loading an
	authenticated page collects it. That is why this used to be unmeasurable — the first
	`/console` load spent the bonus, and the `before` reading taken afterwards already
	contained it, so before == after on every run forever (ADR-0012).

	So the automatic POST is **blocked** for the first load, the true `before` is read,
	and only then is the route posted deliberately. The balance either side of that one
	call is a real before/after, and its answer is a receipt on a site whose quota log
	never records a check-in.

	And when a WAF answers every API path with a JS challenge, a browser is the only
	client that can talk to the site at all: it runs the challenge and moves on.
	"""
	base_url = base_url.rstrip('/')
	root = _root(base_url)
	profile = profile_name(account_name)
	settings = replace(load_browser_login_settings(profile, provider), headless=headless)
	context = await launch_login_context(settings)
	try:
		if open_only and stored_session and not _cookies_named(await context.cookies(), newapi.REFRESH_COOKIE, root):
			# JWT refresh cookies rotate on page load. The live profile is newer than the
			# saved credential; only seed an empty profile, using the actual cookie name.
			await context.add_cookies([{
				'name': newapi.REFRESH_COOKIE, 'value': stored_session, 'domain': root,
				'path': '/', 'secure': base_url.startswith('https://'), 'httpOnly': True,
			}])
		page = await context.new_page()
		await prepare_browser_page(page)
		if open_only:
			# The open-only SPA keeps its Bearer and user in memory, not localStorage.user. Observe
			# the SPA's own refresh: issuing another one races its rotating credential.
			async with page.expect_response(
				lambda r: r.url.split('?', 1)[0] == f'{base_url}{newapi.REFRESH_PATH}', timeout=30_000
			) as refreshed:
				await page.goto(f'{base_url}/console', wait_until='domcontentloaded')
				await wait_for_waf_ready(page)
			response = await refreshed.value
			try:
				body = await response.json() if response.ok else None
			except Exception:  # a WAF/HTML response is not proof of a login
				body = None
			data = body.get('data') if isinstance(body, dict) and body.get('success') is True else None
			user = data.get('user') if isinstance(data, dict) else None
			user = user if isinstance(user, dict) and user.get('id') else None
			after, stamp = await _open_only_allowance(page, data.get('access_token'), user) if user else (None, None)
			session = next(iter(_cookies_named(await context.cookies(), newapi.REFRESH_COOKIE, root)), None)
			return BrowserVisit(before=user, after=after, session=session, checkin_at=stamp, held=False)
		# Hold the SPA's own check-in until the balance has been read, or the bonus lands
		# before anything can measure it — which is the whole bug this exists to prevent.
		held = await _hold_check_in(page)
		await page.goto(f'{base_url}/console', wait_until='domcontentloaded')
		await wait_for_waf_ready(page)
		spa = await _spa_user(context, root)
		before = await _site_user(page, (spa or {}).get('id')) or spa
		if not before and username and password and not open_only:
			await page.goto(f'{base_url}/login', wait_until='domcontentloaded')
			await wait_for_waf_ready(page)
			# relay8 opens the day with an announcement modal over the form, so the
			# username field is there but unreachable — "Cannot open email login form".
			await dismiss_popups(page)
			# The password form is behind 「使用 邮箱或用户名 登录」 — the page starts with only
			# the OAuth buttons, so the username field does not exist until this is clicked.
			await _click_first(page, EMAIL_LOGIN_TEXTS)
			await _accept_terms(page)
			await login_with_email_form(page, username, password, BUTTON_TIMEOUT_MS)
			await asyncio.sleep(3)
			spa = await _spa_user(context, root)
			before = await _site_user(page, (spa or {}).get('id')) or spa
		api_user = (before or spa or {}).get('id')
		# Now collect it on purpose, with the before-balance already in hand.
		await _release_check_in(page)
		path, receipt = await _site_check_in(page, api_user)
		await asyncio.sleep(2)  # the grant is committed before the next read
		after = await _site_user(page, api_user) or await _spa_user(context, root)
		session = next(iter(_cookies_named(await context.cookies(), 'session', root)), None)
		checkin_at = await _site_checkin_at(page, api_user)
		return BrowserVisit(
			before=before,
			after=after,
			session=session,
			checkin_at=checkin_at,
			checkin_path=path,
			receipt=receipt,
			held=held,
		)
	finally:
		await context.close()


async def browser_login(
	*, base_url: str, provider: str, account_name: str, headless: bool = False, _context=None,
	_timeout_s: Optional[float] = None,
) -> BrowserLogin:
	"""Log in within one budget, including launch, navigation and in-page API waits.

	Cancellation unwinds the hop's existing cookie rollback and owned-context close;
	an injected context remains the caller's responsibility to close.
	"""
	timeout_s = _timeout_s if _timeout_s is not None else (SESSION_TIMEOUT_S if headless else HUMAN_TIMEOUT_S)
	budget = asyncio.timeout(timeout_s)
	progress = {'phase': '启动浏览器', 'hosts': ''}
	try:
		async with budget:
			return await _browser_login(
				base_url=base_url, provider=provider, account_name=account_name,
				headless=headless, _context=_context, _progress=progress,
			)
	except TimeoutError as e:
		if not budget.expired():
			raise  # keep the poll loop's observed page/challenge evidence
		raise TimeoutError(f'{timeout_s}s 内没拿到会话（整体登录超时；阶段：{progress["phase"]}；页面域名：{progress["hosts"] or "尚未打开"}）') from e


async def _browser_login(
	*, base_url: str, provider: str, account_name: str, headless: bool = False, _context=None, _progress=None
) -> BrowserLogin:
	"""Log in through `provider`; return the credential to keep and the user behind it.

	The profile lives at <CHECKIN_BROWSER_PROFILE_DIR>/<provider>/<account_name>, so
	two accounts never share an identity and the IdP login survives for next time.
	"""
	progress = _progress if _progress is not None else {}
	buttons = PROVIDER_BUTTONS.get(provider)
	if not buttons:
		raise ValueError(f'{provider} 不是浏览器登录方式，可选: {tuple(PROVIDER_BUTTONS)}')

	base_url = base_url.rstrip('/')
	root = _root(base_url)
	timeout_s = SESSION_TIMEOUT_S if headless else HUMAN_TIMEOUT_S
	# The profile dir is <base>/<provider>/<name>, so the name has to be a legal folder
	# name — and cannot be all dots, or it would land on the parent. Sharing one name
	# means sharing one profile: the store forbids that per site, and across sites it
	# means "the same IdP identity", which is what you want.
	profile = profile_name(account_name)
	# the caller decides visibility; the env default (CHECKIN_HEADLESS) is for CI
	settings = replace(load_browser_login_settings(profile, provider), headless=headless)
	# Injection supplies its still-open context so cookies cannot be overwritten between
	# writing and verification; the outer owner alone closes/releases the profile.
	context = _context if _context is not None else await launch_login_context(settings)
	# What the logout dropped, and whether anything replaced it. A run that ends without a
	# credential puts them back (see `_forget_site`): on a `visit` site the cleared session
	# was the account's whole check-in, and losing it to a click that missed is a regression
	# the owner caused by asking for a login.
	dropped: list[dict] = []
	won = False
	responses = []
	token = None
	token_user = {}
	listening = False
	target = urlsplit(base_url)
	paths = (f'{target.path}/api/user/login', f'{target.path}/api/oauth/{provider}',
		f'{target.path}/api/oauth/{provider}/callback')

	def origin(value):
		port = value.port if value.port is not None else (443 if value.scheme == 'https' else 80)
		return value.scheme, value.hostname, port

	def capture(response):
		# Match the actual target origin, never substrings or the external IdP.
		try:
			url = urlsplit(response.url)
			if origin(url) == origin(target) and not url.username and not url.password and url.path in paths and response.ok:
				responses.append(response)
		except (ValueError, TypeError):
			pass

	try:
		# Before the browser is sent at the IdP: the profile's own Cloudflare state would otherwise
		# make a managed challenge hang instead of clearing on its own. Scoped to the IdP hosts, so
		# the site credential below is untouched by it — and it is not a logout of anything.
		progress['phase'] = '准备站点会话'
		await _clear_cloudflare_state(context, IDP_HOSTS.get(provider, ()))
		dropped = await _forget_site(context, root)
		page = await context.new_page()
		await prepare_browser_page(page)
		progress['phase'] = '打开站点登录页'
		await _goto_login(page, base_url, buttons)
		progress['phase'] = '等待站点页面就绪'
		await wait_for_waf_ready(page)
		await _forget_spa_login(page, base_url, buttons)

		# Twice, because the logout above can cost the OAuth button its own render. These SPAs
		# decide on the *first* paint whether the card shows the provider chooser or the
		# email/password form, and they read that from the site status cached in localStorage —
		# which `_forget_spa_login` has just cleared, having no way to tell a fork's login keys
		# from its config. Measured on relay8: the card comes up as the password form,
		# `/api/status` answers a beat later (200, `linuxdo_oauth: true`) and re-fills the cache,
		# and the card does not repaint — so LinuxDO is nowhere on the page and the run died
		# reporting the site had no LinuxDO login at all. One reload fixes it, because by then
		# the status is cached again. Costs nothing when the button was there the first time.
		progress['phase'] = '点击授权登录'
		context.on('response', capture)
		listening = True
		for attempt in range(2):
			await _unblock_login(page, buttons)  # render, tick the terms box, clear what covers it
			if await _click_first(page, buttons):
				break
			if attempt == 0:
				await _goto_login(page, base_url, buttons)
				await wait_for_waf_ready(page)
		else:
			raise RuntimeError(await _why_no_button(page, buttons, provider))

		# Wall-clock, not a tick count: on a flaky network one whoami blocks for the
		# whole HTTP timeout, and 60 ticks × 25s was a request that never came back.
		deadline = time.monotonic() + timeout_s
		tick = 0
		still = 0  # consecutive ticks in which no page changed URL
		seen: list[str] = []
		# Per page, not per run. The hop is a *chain* of challenged pages
		# (`connect.linux.do/oauth2/authorize` → … → `linux.do/session/sso_provider`), and a run-wide
		# counter let the first page consume the whole budget: measured live 2026-09-14, page 1 spent
		# attempt 1→2 succeeding, page 2 then got only one retry and the deadline ended the run while
		# it was still held. Each page's own attempts are what the cap is about, and the run-wide
		# `deadline` still bounds the total.
		challenge_started: dict[int, tuple[str, float, int]] = {}
		while time.monotonic() < deadline:
			progress['phase'] = '验证站点登录结果'
			found = await _logged_in(context, base_url, root)
			# Drain after verification too: its awaits may deliver the OAuth response.
			while responses:
				response = responses.pop(0)
				try:
					body = await response.json()
				except Exception:  # HTML/WAF/closed responses are not login proof
					continue
				if not isinstance(body, dict) or body.get('success') is not True:
					continue
				data = body.get('data')
				if not isinstance(data, dict):
					continue
				value = data.get('access_token')
				user = data.get('user', data)
				if isinstance(value, str) and value.strip():
					token = value.strip()
					if not token.lower().startswith('bearer '):
						token = f'Bearer {token}'
					token_user = {}
					if isinstance(user, dict) and user.get('id'):
						token_user = {key: val for key, val in user.items() if key not in ('access_token', 'refresh_token')}
			if not found and token and token_user:
				found = ('', token_user)
			if found:
				credential, user = found
				# ponytail: this always re-logs in first, even when the profile is still
				# logged in from yesterday — one OAuth round trip a day. Reuse the live
				# session instead if the launch cost ever matters.
				won = True  # a newer card is in the jar; do not put the old one back over it
				return BrowserLogin(credential, user, token)
			turnstile_clicked = False
			for open_page in list(context.pages):
				if await _click_turnstile(open_page):
					turnstile_clicked = True
			urls = [p.url for p in context.pages]
			# Both sides, not just the IdP. A challenge on the *site's own* page was invisible here
			# because this list was built from `_idp_pages`, which excludes the site tab by
			# construction — so a challenged site page counted as a plain stall and died at
			# STUCK_AFTER_TICKS. Measured 2026-09-14 on grok-heavy: the site's /sign-in served a
			# `challenges.cloudflare.com` frame while the LinuxDO button stayed visible and
			# clickable, the click was accepted mechanically and never navigated, and four
			# consecutive runs died at ~55-60s with 站点自己的页面卡住不动. The arithmetic matches
			# exactly: 15 ticks × POLL_S, with nothing able to hold the counter.
			challenged_pages = []
			for open_page in context.pages:
				if open_page.url in ('', 'about:blank'):
					continue
				if await _challenge_present(open_page):
					challenged_pages.append(open_page)
					state = challenge_started.get(id(open_page))
					if state is None or state[0] != open_page.url:
						challenge_started[id(open_page)] = (open_page.url, time.monotonic(), 1)
			# A challenge that is *present and working* is progress, even though it changes no
			# URL: it holds the stall counter back, but it is never login or check-in proof.
			waiting_on_a_challenge = urls == seen and bool(challenged_pages) and not turnstile_clicked
			still = 0 if turnstile_clicked or waiting_on_a_challenge else still + 1 if urls == seen else 0
			seen = urls
			# A checkbox click is page progress, not login proof. If Cloudflare escalates past
			# the ordinary checkbox, keep the existing bounded IdP/site-specific failure.
			#
			# What to *do* about it differs by side, so the advice is not one sentence. An
			# expired IdP session needs a visible window once. A challenge on the site's own
			# page needs nothing but another go: the run that hit it left the profile holding
			# the `cf_clearance` it earned, so the retry usually walks straight through —
			# telling that owner to log in by hand sends them after a session that is fine.
			if headless:
				# `progress` excuses only the stall shapes — see the docstring. Gating the whole
				# call on it (the old `and not turnstile_clicked`) let a checkbox click suppress
				# the IdP-login verdict every tick, which is how a dead LinuxDO session spent 600s
				# reporting 页面一直在动 instead of saying 需要先人工登录一次 in 10s.
				reason = _why_a_human_is_needed(context, root, tick, still, progress=turnstile_clicked)
				if reason:
					if _idp_pages(context, root):
						raise RuntimeError(
							f'{provider} 需要先人工登录一次（{reason}）：在面板里点「浏览器登录」'
							f'（会打开可见窗口），登录并授权一次后，之后每天都能自动完成。'
						)
					raise RuntimeError(
						f'{reason} —— 这一次没过去，但它挣到的人机验证凭据已经留在 profile 里了，'
						f'直接再试一次通常就能过；连着几次都这样，再点「浏览器登录」开可见窗口看一眼。'
					)
			# A challenge is a stalled navigation, not a failed login — on either side. Restart
			# that same tab after one bounded attempt so its existing session gets a fresh draw.
			# This improves the odds only; Cloudflare can still hold every attempt. `_logged_in`
			# ran first this tick, so a proven login can never be disturbed by this branch.
			now = time.monotonic()
			for open_page in challenged_pages:
				state = challenge_started.get(id(open_page))
				if not state or state[2] >= IDP_CHALLENGE_MAX_ATTEMPTS:
					continue
				if now - state[1] < IDP_CHALLENGE_ATTEMPT_S:
					continue
				if any(mark in open_page.url for mark in IDP_LOGIN_MARKS):
					continue
				# Never re-navigate a page that already *won*. A callback carrying the
				# authorization — measured 2026-09-14 at
				# `connect.linux.do/discourse/sso_callback?sso=<base64 assertion>` — is the hop's
				# product; sending the browser back to the authorize URL throws it away and
				# restarts the whole round trip, which repeated until the deadline. `sso_provider`
				# is deliberately NOT on this list: it is an intermediate page in the same measured
				# chain and it may itself be challenged.
				if any(mark in state[0] for mark in IDP_CALLBACK_MARKS):
					continue
				on_the_site = root in state[0]
				try:
					await open_page.goto(state[0], wait_until='domcontentloaded')
				except Exception:
					# `net::ERR_ABORTED` is the *good* case, not a failure: the challenge let the
					# tab go and Cloudflare redirected it out from under this navigation. Playwright
					# raises for that, and letting it escape killed a live run at 143s after its
					# retry had already worked (2026-09-14, grok-heavy). Nothing is claimed here —
					# the next tick re-reads URLs and `_logged_in` decides.
					pass
				if on_the_site:
					# Re-navigating is not enough on this side. The pre-loop's *click* is what
					# starts the OAuth hop, and the poll loop never re-clicks — so a reload alone
					# lands back on a login card nobody presses again. Measured 2026-09-14: the
					# LinuxDO button stayed visible and clickable behind the site's own challenge,
					# the click was accepted mechanically, and the page never moved. Same bounded
					# attempt budget; a click is browser progress and never login proof.
					await _unblock_login(open_page, buttons)
					await _click_first(open_page, buttons)
				challenge_started[id(open_page)] = (state[0], time.monotonic(), state[2] + 1)
				seen = []
				still = 0
				break
			progress['phase'] = '等待授权跳转或确认'
			for open_page in context.pages:  # consent may be a popup or the same tab
				if 'oauth' in open_page.url or 'authorize' in open_page.url:
					await dismiss_popups(open_page)
					await _click_first(open_page, CONSENT_TEXTS, timeout_ms=CONSENT_TIMEOUT_MS)
			tick += 1
			await asyncio.sleep(POLL_S)
		# Reaching here means either nothing ever sat still long enough to be called stuck, or an
		# IdP tab spent the whole budget on a challenge that is still there. Both end the same way
		# and neither is named as a cause we did not observe — the pages are the evidence there is.
		#
		# Say what was *observed*: the pages the run ended on, and whether the challenge signature
		# was still readable on them. Never "Cloudflare never let it through" — the marker is a weak
		# signal (these hosts serve it on ordinary pages too: measured 2026-09-14, a plain GET of
		# linux.do and connect.linux.do answers 403 `Just a moment...` with `cf-mitigated: challenge`,
		# and the marker was still in the document of a tab that had already been *authorized*).
		#
		# Both sides, to match where the challenge list is built: the site's own page carries a
		# Turnstile widget by design (`TURNSTILE_PAGES`), so restricting this to `_idp_pages` would
		# report "pages kept moving" for a site page that was doing the opposite.
		parked = [p.url for p in context.pages if p.url not in ('', 'about:blank')]
		challenged = []
		for open_page in context.pages:
			if open_page.url in ('', 'about:blank'):
				continue
			if await _challenge_present(open_page):
				challenged.append(open_page.url)
		if challenged:
			raise TimeoutError(
				f'{timeout_s}s 内没拿到会话：结束前这些页面上仍能读到人机验证的特征'
				f'（该特征在正常页面上也会出现，所以它只说明停在原地，不代表验证没过）；'
				f'直接再试一次，或者点「浏览器登录」开可见窗口看一眼。当前页面: {" | ".join(challenged)}'
			)
		raise TimeoutError(
			f'{timeout_s}s 内没拿到会话，页面一直在动、没有停下来过；'
			f'当前页面: {" | ".join(parked)}'
		)
	finally:
		if listening:
			context.remove_listener('response', capture)
		# Host names alone: paths, query parameters and fragments can carry OAuth secrets.
		hosts = set()
		for open_page in context.pages:
			try:
				host = urlsplit(open_page.url).hostname
				if host:
					hosts.add(host)
			except (ValueError, TypeError):
				pass
		progress['hosts'] = ', '.join(sorted(hosts))
		try:
			if dropped and not won:
				try:
					await context.add_cookies(dropped)
				except Exception:
					pass
		finally:
			if _context is None:
				await context.close()


# What an exported cookie's `sameSite` is called on each side. A browser extension exports
# Chrome's own vocabulary; Playwright takes the header's. An unlisted value (Chrome's
# 'unspecified') means "do not send the attribute at all", so it maps to nothing.
SAME_SITE = {'no_restriction': 'None', 'lax': 'Lax', 'strict': 'Strict'}
# Fields Playwright accepts. Everything else an extension exports — `hostOnly`, `storeId`,
# `id`, and the `session` boolean — has to be dropped: an unknown key is rejected outright.
COOKIE_FIELDS = ('name', 'value', 'domain', 'path', 'secure', 'httpOnly')
# Where each provider's own session lives, for warning about an export from the wrong tab.
# Not a filter: LinuxDO authorises at connect.linux.do while its session cookie is on
# linux.do, so the relationship is not one host to one provider.
IDP_HOSTS = {'linuxdo': ('linux.do',), 'github': ('github.com',)}


def playwright_cookies(raw: Optional[str]) -> list[dict]:
	"""An exported cookie jar, in the shape `context.add_cookies` accepts. Raises if it is not one.

	Two vocabularies have to be reconciled, and getting either wrong is rejected rather than
	ignored: `expirationDate` is Playwright's `expires`, and a session cookie has no expiry
	at all — sending one anyway pins a cookie that was meant to die with the browser.
	"""
	text = (raw or '').strip()
	if not text:
		raise ValueError('没有粘贴任何内容')
	try:
		parsed = json.loads(text)
	except json.JSONDecodeError as e:
		raise ValueError(
			f'这段内容不是有效的 JSON：{e.msg}（第 {e.lineno} 行）。'
			'请用 cookie 扩展的「导出 / Export」把整段 JSON 复制过来'
		) from e
	rows = parsed if isinstance(parsed, list) else [parsed]
	cookies = []
	for row in rows:
		if not isinstance(row, dict):
			continue
		name, value, domain = row.get('name'), row.get('value'), row.get('domain')
		if not (isinstance(name, str) and name and isinstance(value, str) and isinstance(domain, str) and domain):
			continue
		cookie = {k: row[k] for k in COOKIE_FIELDS if k in row}
		cookie['path'] = row.get('path') or '/'
		expires = row.get('expirationDate', row.get('expires'))
		if isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires > 0:
			cookie['expires'] = float(expires)
		same_site = SAME_SITE.get(str(row.get('sameSite') or '').lower())
		if same_site:
			cookie['sameSite'] = same_site
		cookies.append(cookie)
	if not cookies:
		raise ValueError(
			'这段 JSON 里没有一条可用的 cookie（每条至少要有 name、value、domain）。'
			'请确认导出的是 cookie 列表，而不是别的东西'
		)
	return cookies


@dataclass
class IdpInjection:
	"""What one IdP-cookie injection did, and whether the profile now really logs in.

	`verified` is three-valued on purpose: True means a headless OAuth hop just completed
	with these cookies, False means it did not, and None means nobody asked. Only True is
	evidence — the whole reason to verify on the spot is that "the cookies went in" says
	nothing about whether the IdP accepts them.
	"""

	injected: int
	hosts: tuple[str, ...]
	verified: Optional[bool] = None
	credential: Optional[str] = None  # the site session verification won, worth storing
	api_user: Optional[str] = None
	reason: Optional[str] = None  # why verification failed, in the owner's words
	warning: Optional[str] = None
	access_token: Optional[str] = None


async def inject_idp_cookies(
	raw: str, *, provider: str, account_name: str, base_url: str, verify: bool = True
) -> IdpInjection:
	"""Load an exported IdP session into this account's profile, then prove it works.

	The profile is the one `browser_login` uses, keyed exactly the same way — a different
	name here would write a session into a directory nothing reads.

	Normalising happens before the browser is launched, so a paste that is not a cookie jar
	cannot leave a half-written profile behind.
	"""
	if provider not in PROVIDER_BUTTONS:
		raise ValueError(f'{provider} 不是授权登录方式，可选: {tuple(PROVIDER_BUTTONS)}')
	cookies = playwright_cookies(raw)
	hosts = tuple(sorted({c['domain'].lstrip('.') for c in cookies}))
	expected = IDP_HOSTS.get(provider, ())
	warning = None
	if expected and not any(host.endswith(e) for host in hosts for e in expected):
		# Worth saying, not worth refusing: an export may legitimately come from a host this
		# table does not know, and refusing would block a paste that works.
		warning = (
			f'这段 cookie 来自 {"、".join(hosts)}，看着不像 {provider}'
			f'（一般是 {"、".join(expected)}）——登录不上的话，先确认导出的标签页对不对'
		)

	profile = profile_name(account_name)
	# Headless regardless of the env default: this launch only writes cookies to disk, so a
	# window would flash open for no one to look at.
	settings = replace(load_browser_login_settings(profile, provider), headless=True)
	context = None
	injected = False
	phase = '启动浏览器'
	budget = asyncio.timeout(INJECTION_TIMEOUT_S)
	try:
		async with budget:
			# Launch owns any late context on cancellation; once returned, this function owns close.
			context = await launch_login_context(settings)
			phase = '写入 cookie'
			await context.add_cookies(cookies)
			injected = True
			if not verify:
				return IdpInjection(len(cookies), hosts, warning=warning)
			phase = '验证会话'
			try:
				result = await browser_login(
					base_url=base_url, provider=provider, account_name=account_name,
					headless=True, _context=context, _timeout_s=INJECTION_VERIFY_TIMEOUT_S,
				)
			except Exception as e:
				return IdpInjection(len(cookies), hosts, verified=False, reason=newapi.why(e), warning=warning)
			return IdpInjection(
				len(cookies), hosts, verified=True, credential=result.credential,
				api_user=str(result.user.get('id') or '') or None, warning=warning, access_token=result.access_token,
			)
	except TimeoutError as e:
		if not budget.expired():
			raise
		if injected:
			return IdpInjection(
				len(cookies), hosts, verified=False, warning=warning,
				reason=f'{INJECTION_TIMEOUT_S}s 整体导入超时（{phase}）；已写入的 IdP cookie 保留，未确认站点会话',
			)
		raise TimeoutError(f'{INJECTION_TIMEOUT_S}s 整体导入超时（{phase}），未确认 cookie 注入完成') from e
	finally:
		# Do not deadline or detach close: the shielded context keeps its lease until Chromium exits.
		if context is not None:
			await context.close()
