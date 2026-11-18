"""FastAPI application for the Check-in Panel.

Serves the API and built frontend. Credentials are write-only. Loopback Host and
same-origin browser checks protect the default local deployment. This is still a
single-user application without authentication: remote use requires an authenticated
reverse proxy/private network and explicitly configured PANEL_ALLOWED_ORIGINS.
"""
import asyncio
import os
import re
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from panel import newapi, promo, scheduler
from panel.service import CheckInService, CredentialCheck
from panel.store import LOGIN_METHODS, MECHANISMS, AccountStore
from panel.vendor.utils.browser import ProfileBusyError


class AccountIn(BaseModel):
	name: str
	base_url: str
	login_method: str = 'password'
	mechanism: Optional[str] = None
	username: Optional[str] = None
	password: Optional[str] = None
	access_token: Optional[str] = None
	session: Optional[str] = None
	api_user: Optional[str] = None
	checkin_after: Optional[str] = None
	avatar_color: Optional[str] = None
	avatar_shape: Optional[str] = None
	enabled: Optional[bool] = None


class AccountPatch(AccountIn):
	name: Optional[str] = None
	base_url: Optional[str] = None
	login_method: Optional[str] = None


class AccountOut(BaseModel):
	"""Public account fields only; storage additions are not implicitly exposed."""
	id: int
	name: str
	base_url: str
	login_method: str
	mechanism: Optional[str]
	username: Optional[str]
	api_user: Optional[str]
	checkin_after: Optional[str]
	avatar_color: Optional[str]
	avatar_shape: Optional[str]
	enabled: bool
	last_run_at: Optional[str]
	last_success: Optional[bool]
	last_checked_in: Optional[bool]
	last_quota: Optional[float]
	last_error: Optional[str]
	failures: int
	created_at: Optional[str]
	updated_at: Optional[str]
	has_password: bool
	has_session: bool
	has_access_token: bool


class AccountSavedOut(BaseModel):
	account: AccountOut
	credential: Optional[dict]


class IdsIn(BaseModel):
	account_ids: list[int]


class ProbeIn(BaseModel):
	base_url: str


class BrowserLoginIn(BaseModel):
	headless: bool = False
	set_password: bool = True


class IdpCookiesIn(BaseModel):
	cookies: str
	verify: bool = True


class ProfileKeysIn(BaseModel):
	"""Which orphaned profiles to delete, as `<provider>/<name>` or a bare `<name>` for one
	from the old layout — the path relative to the profile root, either way."""

	keys: list[str]


WINDOW = re.compile(r'([01]?\d|2[0-3]):[0-5]\d')
# Avatar colour/shape are slugs whose meaning lives in frontend/src/avatar.ts. Checking
# only the shape keeps the palette in one place; an unknown slug falls back there, so the
# backend never has to learn a colour name to accept one.
AVATAR_SLUG = re.compile(r'[a-z]{2,16}')
DUPLICATE = '这个网站下已经有同名账号了；换个名称（名称也决定浏览器 profile，重名会共用同一个身份）'


def _check(payload: AccountIn) -> dict:
	fields = payload.model_dump(exclude_none=True)
	# PATCH semantics: omission preserves; explicit null clears a credential.
	if isinstance(payload, AccountPatch):
		for key in ('password', 'session', 'access_token'):
			if key in payload.model_fields_set:
				fields[key] = getattr(payload, key) or ''
	url = fields.get('base_url')
	if url is not None and not str(url).startswith(('http://', 'https://')):
		raise HTTPException(status_code=422, detail='base_url 必须以 http:// 或 https:// 开头')
	method = fields.get('login_method')
	if method is not None and method not in LOGIN_METHODS:
		raise HTTPException(status_code=422, detail=f'login_method 必须是 {LOGIN_METHODS} 之一')
	mechanism = fields.get('mechanism')
	if mechanism is not None and mechanism not in MECHANISMS:
		raise HTTPException(status_code=422, detail=f'签到方式必须是 {MECHANISMS} 之一')
	window = fields.get('checkin_after')
	if window and not WINDOW.fullmatch(str(window)):
		raise HTTPException(status_code=422, detail='每日开放时间要写成 HH:MM，例如 08:30')
	for key, label in (('avatar_color', '头像颜色'), ('avatar_shape', '头像样式')):
		value = fields.get(key)
		if value is not None and not AVATAR_SLUG.fullmatch(str(value)):
			raise HTTPException(status_code=422, detail=f'{label}要写成 2-16 位小写英文，例如 blue')
	return fields


def _pasted(fields: dict) -> Optional[list[newapi.PastedCredential]]:
	"""Read the `session` field as something a human pasted, and normalise it in place.

	Whatever shape it arrived in — a bare value, a `session=…` header, a whole exported cookie
	jar — the column stores the credential itself. Storing the JSON document instead is how a
	paste-format mistake ended up wearing the site's error message: it authenticates against
	nothing, and the site answers 凭据无效, which reads as an expired session.

	A paste with no credential in it is a 422 and nothing is written; a credential that turns
	out not to authenticate is not (that is `verify_credential`'s business, and ADR-0010 is the
	reason it cannot be an error — a WAF refuses good credentials too).
	"""
	raw = fields.get('session')
	if not raw:
		return None
	try:
		candidates = newapi.credentials_from_paste(raw)
	except ValueError as e:
		raise HTTPException(status_code=422, detail=str(e)) from None
	fields['session'] = candidates[0].value
	return candidates


def _account(account) -> dict:
	"""Only credential presence crosses the API; omitted edit fields preserve stored values."""
	body = asdict(account)
	for key in ('password', 'session', 'access_token'):
		body[f'has_{key}'] = bool(body.pop(key, None))
	return AccountOut.model_validate(body).model_dump()


def _outcome(outcome: newapi.Outcome) -> dict:
	body = asdict(outcome)
	body.pop('session', None)  # never hand a session back to the browser
	body.pop('access_token', None)
	body['delta'] = outcome.delta
	body['gain'] = outcome.gain  # the site's own figure where it gave one, else the delta
	return body


def create_app(
	*,
	store: AccountStore,
	service: CheckInService,
	enable_scheduler: bool = False,
	dist_dir: Optional[Path] = None,
) -> FastAPI:
	"""Build the app. `dist_dir` serves the built SPA when given; API only when None.

	Every entry point passes a `dist_dir` that already exists (`sandbox.prepare()` returns
	None when the frontend was never built), so a missing directory is a caller bug rather
	than something to paper over here.
	"""

	@asynccontextmanager
	async def lifespan(_app: FastAPI):
		task = asyncio.create_task(scheduler.loop(store, service)) if enable_scheduler else None
		try:
			yield
		finally:
			if task:
				task.cancel()
				await asyncio.gather(task, return_exceptions=True)

	app = FastAPI(title='Check-in Panel', lifespan=lifespan)
	# Exact public origins explicitly configured by the operator also authorize their Host.
	# A proxy can preserve Host or forward to loopback; no forwarded header grants trust.
	allowed_origins = {item.strip().rstrip('/') for item in os.getenv('PANEL_ALLOWED_ORIGINS', '').split(',') if item.strip()}
	trusted_hosts = {'localhost', '127.0.0.1', '::1'}
	for origin in allowed_origins:
		parsed = urlsplit(origin)
		if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or '*' in origin:
			raise ValueError('PANEL_ALLOWED_ORIGINS must contain exact http(s) origins')
		trusted_hosts.add(parsed.hostname)

	@app.middleware('http')
	async def browser_boundary(request: Request, call_next):
		try:
			host = urlsplit('//' + request.headers.get('host', ''))
			valid_host = host.hostname in trusted_hosts and not host.username and not host.password and not host.path and not host.query and not host.fragment
			_ = host.port  # Reject malformed ports as well.
		except ValueError:
			valid_host = False
		if not valid_host:
			return JSONResponse({'detail': 'Untrusted Host'}, status_code=400)
		if request.method not in ('GET', 'HEAD', 'OPTIONS'):
			origin = request.headers.get('origin')
			local_origin = f'{request.url.scheme}://{request.headers["host"]}'
			if request.headers.get('sec-fetch-site') == 'cross-site' or (origin is not None and origin not in allowed_origins and origin != local_origin):
				return JSONResponse({'detail': 'Cross-origin request refused'}, status_code=403)
		response = await call_next(request)
		if request.url.path.startswith('/api/'):
			response.headers['Cache-Control'] = 'no-store'
		return response

	def _require(account_id: int):
		account = store.get(account_id)
		if account is None:
			raise HTTPException(status_code=404, detail='Account not found')
		return account

	async def _with_credential(account_id: int, candidates, fields: dict) -> dict:
		"""The saved account, plus what its credential turned out to be worth.

		`credential` is null when this request carried none, so a caller that only sets a name
		sees the same thing it always did. When there is one it is checked here rather than in
		a route of its own: a JWT fork's refresh cookie is *spent* by the check and replaced,
		so the verification has to happen where the replacement can be stored in the same
		breath (`service.verify_credential`). A separate stateless route would either hand the
		rotated value back to the browser — which this API never does for a credential — or
		burn the credential and drop it.

		An **access token** counts as a pasted credential too, and it arrives in its own field
		rather than as a jar `_pasted` can read. Leaving it out meant the one credential a
		headless deployment is most likely to use was the only one saved unverified — wrong
		until tomorrow's failed run.
		"""
		if not candidates and not fields.get('access_token'):
			return {'account': _account(_require(account_id)), 'credential': None}
		try:
			check = await service.verify_credential(account_id, candidates)
		except Exception as e:  # a probe that failed must not lose the account that was saved
			check = CredentialCheck(False, reason=f'凭据没能验证：{newapi.why(e)}')
		body = asdict(check)
		body['warning'] = None if check.ok else check.reason
		return {'account': _account(_require(account_id)), 'credential': body}

	@app.get('/api/accounts', response_model=list[AccountOut])
	def list_accounts():
		return [_account(a) for a in store.list()]

	@app.post('/api/accounts', status_code=201, response_model=AccountSavedOut)
	async def create_account(payload: AccountIn):
		fields = _check(payload)
		candidates = _pasted(fields)
		try:
			account = store.create(**fields)
		except sqlite3.IntegrityError:
			raise HTTPException(status_code=409, detail=DUPLICATE) from None
		return await _with_credential(account.id, candidates, fields)

	@app.get('/api/accounts/{account_id}', response_model=AccountOut)
	def get_account(account_id: int):
		return _account(_require(account_id))

	@app.put('/api/accounts/{account_id}', response_model=AccountSavedOut)
	async def update_account(account_id: int, payload: AccountPatch):
		before = _require(account_id)
		fields = _check(payload)
		candidates = _pasted(fields)
		# Verifying costs something on a JWT fork: the check *spends* the refresh cookie and
		# rotates it, which logs out everyone else holding that value — including the owner's
		# own browser. The UI now omits unchanged credentials, but older clients and CLI callers
		# can still explicitly resubmit the same value. Do not burn a rotation for that rename.
		# Only a changed credential is worth checking; `checkable` therefore
		# carries what this request *changed*, while `fields` still carries everything to store.
		checkable = dict(fields)
		if candidates and fields.get('session') == before.session:
			candidates = None
		if checkable.get('access_token') == before.access_token:
			checkable.pop('access_token', None)
		try:
			store.update(account_id, **fields)
		except sqlite3.IntegrityError:
			raise HTTPException(status_code=409, detail=DUPLICATE) from None
		return await _with_credential(account_id, candidates, checkable)

	@app.delete('/api/accounts/{account_id}')
	def delete_account(account_id: int, forget_profile: bool = True):
		"""Delete an account, and by default its browser profile.

		A query flag rather than a body, because DELETE bodies are not reliably carried, and
		defaulting to true rather than false because of what the profile holds: the IdP
		session, i.e. the whole forum or GitHub login. Leaving it behind is how a deleted
		account's credential stayed on disk with nothing naming the directory.

		No longer 204: the answer says whether a profile was really removed, which is the one
		thing the caller cannot work out for itself.
		"""
		_require(account_id)
		return {'profile_removed': service.delete(account_id, forget_profile=forget_profile)}

	@app.get('/api/profiles/orphans')
	def orphan_profiles():
		"""Browser profiles on disk that no account claims — a rename or an old layout leaves
		these behind, and each one may still hold a live IdP session."""
		found = service.orphan_profiles()
		return {
			'profiles': [
				{'key': o.key, 'name': o.name, 'provider': o.provider, 'bytes': o.bytes, 'old_layout': o.old_layout}
				for o in found
			],
			'bytes': sum(o.bytes for o in found),
		}

	@app.post('/api/profiles/orphans/delete')
	def delete_orphan_profiles(payload: ProfileKeysIn):
		"""Delete the listed orphans. Takes keys from the listing above rather than deleting
		everything unclaimed, so the owner's decision is what runs and not a re-derivation of
		it; anything that stopped being an orphan meanwhile is skipped."""
		return {'removed': service.delete_orphan_profiles(payload.keys)}

	@app.post('/api/accounts/{account_id}/check-in')
	async def check_in(account_id: int):
		_require(account_id)
		return _outcome(await service.check_in(account_id))

	@app.post('/api/check-in')
	async def check_in_many(payload: IdsIn):
		results = await service.check_in_many(payload.account_ids)
		return {str(k): _outcome(v) for k, v in results.items()}

	@app.post('/api/probe')
	async def probe(payload: ProbeIn):
		_check(AccountIn(name='probe', base_url=payload.base_url))
		try:
			info = await service.probe(payload.base_url)
		except Exception as e:
			raise HTTPException(status_code=502, detail=newapi.why(e)) from e
		return {**asdict(info), 'mechanism': info.mechanism}

	@app.post('/api/accounts/{account_id}/bootstrap')
	async def bootstrap(account_id: int):
		_require(account_id)
		try:
			username = await service.bootstrap(account_id)
		except Exception as e:
			raise HTTPException(status_code=400, detail=str(e)) from e
		return {'username': username}

	@app.post('/api/accounts/{account_id}/browser-login')
	async def browser_login(account_id: int, payload: BrowserLoginIn):
		"""Drive a real browser through the account's OAuth provider and keep the
		session. With `set_password` it also tries to trade that session for a
		password, which retires the browser for good — forks that verify
		`original_password` refuse, and the account stays on the browser path
		(ADR-0009)."""
		account = _require(account_id)
		try:
			# Imported inside the try because it is not always importable: the container
			# image and a browser-less install have no cloakbrowser, and an ImportError out
			# here is a 500 that says nothing. Inside, it is a 400 that names the cause.
			from panel.browser_login import browser_login as run_browser_login

			result = await run_browser_login(
				base_url=account.base_url,
				provider=account.login_method,
				account_name=account.name,
				headless=payload.headless,
			)
		except Exception as e:
			raise HTTPException(status_code=409 if isinstance(e, ProfileBusyError) else 400, detail=newapi.why(e)) from e
		store.update(account_id, session=result.credential, api_user=result.user.get('id'), access_token=result.access_token or '')
		# The credential just changed, so the stored result describes a run made with the old
		# one — leaving it makes the list show 「refresh 凭据已失效」 beside an account that has
		# since logged in fine. Back to unknown, not to success: no check-in happened here, and
		# only a real run may claim one.
		store.reset_result(account_id)
		username = None
		if payload.set_password:
			try:
				username = await service.bootstrap(account_id)
			except Exception as e:
				return {'session_stored': True, 'username': None, 'warning': str(e)}
		return {'session_stored': True, 'username': username}

	@app.post('/api/accounts/{account_id}/idp-cookies')
	async def idp_cookies(account_id: int, payload: IdpCookiesIn):
		"""Load an exported IdP session into this account's browser profile.

		The server-deployment path for an OAuth-only account. Its site session is renewed
		every day by a headless OAuth hop, but the IdP session that hop renews *from*
		normally arrives through one visible window (ADR-0009) — which a headless box cannot
		offer. This supplies it as cookie values instead, and `verify` proves on the spot that
		the hop now completes, rather than leaving it to be discovered tomorrow.

		Note what crosses this API: an IdP session cookie is the whole account at
		linux.do or github.com, and the panel has no auth layer (ADR-0003). The cookies
		are written into the profile and **not** stored by the panel — the profile is where
		that secret already lives after any ordinary browser login.
		"""
		_require(account_id)
		try:
			# Imported inside the try for the same reason as browser-login above: a
			# browser-less install has no cloakbrowser, and an ImportError out here is a 500
			# that says nothing.
			result = await service.inject_idp_cookies(account_id, payload.cookies, verify=payload.verify)
		except ValueError as e:  # not a cookie jar, or the wrong provider — nothing was touched
			raise HTTPException(status_code=422, detail=str(e)) from None
		except Exception as e:
			raise HTTPException(status_code=409 if isinstance(e, ProfileBusyError) else 400, detail=newapi.why(e)) from e
		# The site session the verification won is already stored; it must not travel back.
		# This API never hands a credential to the browser, and the caller has no use for it.
		return {k: v for k, v in asdict(result).items() if k not in ('credential', 'access_token')}

	@app.get('/api/promos')
	async def promos():
		"""The one promo card to show right now, or none.

		A promotion is never worth a failure: an unreachable manifest, a broken one, or a
		state write that did not land all answer 200 with `card: null` rather than making
		the panel look broken. Targeting happens here, from the local database — the manifest
		fetch itself learns nothing about this install (panel/promo.py)."""
		try:
			cards = await promo.cards()
			if not cards:
				return {'card': None}
			accounts = store.list()
			state = store.promo_state()
			card = promo.pick(
				cards,
				hosts=promo.hosts_of(accounts),
				panel_age_h=promo.panel_age_h(accounts),
				account_count=len(accounts),
				state=state,
			)
			if card is None:
				return {'card': None}
			# The sticker is read before the impression is written: promo_seen() creates the row
			# whose first_seen_at decides whether this card is still new.
			seen = state.get(card.id)
			if promo.due_for_impression(seen):
				store.promo_seen(card.id)
			return {'card': card.payload(sticker=promo.sticker_for(seen))}
		except Exception as e:
			print(f'[PROMO] /api/promos 失败：{type(e).__name__}: {e}')
			return {'card': None}

	@app.post('/api/promos/{promo_id}/dismiss', status_code=204)
	def dismiss_promo(promo_id: str):
		"""Closed for good, until the card's own cooldown expires. The id is capped because
		it comes back from the browser and each distinct value is a row."""
		store.promo_dismiss(promo_id[:64])

	@app.get('/api/health')
	def health():
		"""Liveness for a container healthcheck. Static on purpose.

		A healthcheck runs unauthenticated every few seconds and its URL ends up in
		`docker inspect`, image metadata and logs, so this route must never read an
		account — `/api/accounts` returns credentials in the clear (ADR-0003).
		"""
		return {'status': 'ok', 'scheduler': enable_scheduler}

	if dist_dir is not None:
		app.mount('/assets', StaticFiles(directory=dist_dir / 'assets'), name='assets')

		@app.get('/')
		def index():
			return FileResponse(dist_dir / 'index.html')

		@app.get('/accounts/{path:path}')
		def spa_fallback(path: str):
			return FileResponse(dist_dir / 'index.html')

	return app
