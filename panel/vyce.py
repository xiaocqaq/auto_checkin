"""relay4 —— 自建后端的签到实现（不是 New API / One API 分支）。

为什么单独一个模块：New API 系的公开面是 `/api/status` + `/api/user/login` +
`/api/user/checkin`，而这个站是自建后端，路由全在 `/user/*`，登录还带一道
**工作量证明**，`newapi.py` 的 client 一行都用不上。签名/数据结构如下（均实测）：

    GET  /user/csrf                 -> {token}                登录前置 CSRF
    GET  /user/pow?purpose=login    -> {id,prefix,salt,difficulty,v,epoch,expiresAt,purpose}
    POST /user/login                -> {token, user}          token 值 == session cookie 值
    GET  /user/daily-reward         -> {canClaim,streak,lastClaim,rewardAmount,totalClaimed,...}
    POST /user/daily-reward/claim   -> 领取；**无 body、无验证码**，已领则 400
                                       `Already claimed today. Come back tomorrow!`
    GET  /user/balance              -> {totalBalance, tier, ...}

登录门槛是一个 SHA-256 工作量证明（PoW），纯 CPU，不需要浏览器也不需要验证码：
找 nonce `g`，使

    b   = sha256(f'vyce-pow-v4:{salt}:{prefix}:{id}:{g}:{purpose}').hexdigest()
    seal= sha256(f'vyce-auth-seal-v4:{id[:32]}:{b}:{g}:{epoch}').digest()

且 `seal` 的前导零位（bit）>= `difficulty`。实测 difficulty=17 时 ≈13 万次哈希、
0.04~0.9 秒就能命中（哈希分布随机，快慢差 20 倍很正常）。

会话：登录返回的 `session_xxx` 就是凭据，`Max-Age=604800`（7 天），
`HttpOnly; SameSite=Lax; Secure`。带上它就能直接 claim，**不需要再带 Bearer**；
失效时 `GET /user/daily-reward` 回 401 `invalid_session`。所以把 cookie 存进面板的
`session` 字段即可，下次运行先试探再决定要不要重新登录。
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from typing import Optional

import httpx
from urllib.parse import urlparse

from panel.newapi import Login, Outcome, SiteInfo

# 探测用：这个路径只有自建后端才有，New API 系会 404 或者被 WAF 换成 HTML。
DAILY_REWARD_PATH = '/user/daily-reward'
CLAIM_PATH = '/user/daily-reward/claim'
CSRF_PATH = '/user/csrf'
POW_PATH = '/user/pow'
LOGIN_PATH = '/user/login'
BALANCE_PATH = '/user/balance'

TIMEOUT_S = 90.0  # 实测（2026-10-23）该站经本机 mihomo 出网单请求 9~22 秒，30 秒必然撞超时
CONNECT_S = 15.0  # 建连给到 15 秒：代理握手偶发慢，8 秒会误判成站点挂了
POW_DEADLINE_S = 60.0  # 客户端解 PoW 的硬上限；实测最坏 0.9 秒，60 秒是给慢机器留的余量
UA = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
	'(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
)

ALREADY_DONE = re.compile(r'already\s+claimed', re.I)


# ─────────────────────────── PoW ─────────────────────────────
def _leading_zero_bits(data: bytes) -> int:
	"""`seal` 前面连续为 0 的 bit 数。与前端 `Nu()` 的判定等价。"""
	count = 0
	for byte in data:
		if byte == 0:
			count += 8
			continue
		count += 8 - byte.bit_length()
		break
	return count


def _solve_pow(
	challenge_id: str, prefix: str, salt: Optional[str], difficulty: int,
	purpose: str, epoch: int, deadline_s: float = POW_DEADLINE_S,
) -> Optional[int]:
	"""暴力搜 nonce。返回命中的 `g`；超时返回 None。

	拆成两趟哈希是因为服务端要校验「pow 串的哈希」被「seal 串」封住，防的是别人拿现成
	的 pow 串去换别的 epoch。两趟都不能省。
	"""
	salt = salt or ''
	sealed = challenge_id[:32]
	g = 0
	started = time.time()
	while time.time() - started < deadline_s:
		# 分批，好让超时判定有机会执行（一整个 while 里跑满 20 万次也才零点几秒）
		for _ in range(200_000):
			b = hashlib.sha256(
				f'vyce-pow-v4:{salt}:{prefix}:{challenge_id}:{g}:{purpose}'.encode()
			).hexdigest()
			seal = hashlib.sha256(
				f'vyce-auth-seal-v4:{sealed}:{b}:{g}:{epoch}'.encode()
			).digest()
			if _leading_zero_bits(seal) >= difficulty:
				return g
			g += 1
	return None


# ─────────────────────────── HTTP ─────────────────────────────
def _proxy() -> Optional[str]:
	"""和面板其它请求同一个出口（国内直连不到被墙站点；本机出网只能经 mihomo）。"""
	return (os.getenv('CHECKIN_HTTP_PROXY') or os.getenv('CHECKIN_PROXY_URL') or '').strip() or None


def _client(base_url: str, session: Optional[str] = None) -> httpx.AsyncClient:
	headers = {
		'Accept': 'application/json, text/plain, */*',
		'User-Agent': UA,
		# 这个站的 fetch 带 credentials:'include'，且后端会看 Origin；缺了容易吃 403。
		'Origin': base_url.rstrip('/'),
		'Referer': base_url.rstrip('/') + '/',
	}
	return httpx.AsyncClient(
		base_url=base_url.rstrip('/'),
		timeout=httpx.Timeout(TIMEOUT_S, connect=CONNECT_S),
		headers=headers,
		cookies={'session': session} if session else None,
		follow_redirects=True,
		proxy=_proxy(),
		trust_env=False,
	)


def _json(response: httpx.Response) -> dict:
	try:
		body = response.json()
	except ValueError:
		return {}
	return body if isinstance(body, dict) else {}


def _error_of(response: httpx.Response, body: dict) -> str:
	"""这个站的错误是 OpenAI 形状：`{"error": {"message": ...}}`。"""
	err = body.get('error')
	if isinstance(err, dict):
		message = err.get('message')
		if message:
			return str(message)
	if isinstance(err, str) and err:
		return err
	return body.get('message') or f'HTTP {response.status_code}'


# ─────────────────────────── 登录 ─────────────────────────────
def _fingerprint_for(username: str) -> tuple[str, str]:
	"""按账号派生的稳定设备指纹。

	站点在前端用 canvas/WebGL 采一份指纹并在登录时上报；我们自己拼一个，但**必须逐次
	稳定**——每次登录都换一台"新设备"是最容易被风控盯上的行为，上游浏览器指纹那次的
	教训一样（ cloakbrowser 每次随机抽种子，同一 profile 天天变新设备）。
	"""
	seed = username.strip().lower().encode()
	fp = hashlib.sha256(b'checkin-panel-fp:' + seed).hexdigest()
	machine = hashlib.sha256(b'checkin-panel-machine:' + seed).hexdigest()[:32]
	return fp, machine


async def _login(client: httpx.AsyncClient, login: Login) -> tuple[Optional[str], Optional[str]]:
	"""充值一步登录。返回 `(session_cookie, error)`。"""
	if not (login.username and login.password):
		return None, '该站靠账号密码登录，当前凭据没有密码'

	response = await client.get(CSRF_PATH)
	csrf = _json(response).get('token')
	if not isinstance(csrf, str) or len(csrf) < 32:
		return None, f'取 CSRF 失败: {_error_of(response, _json(response))}'

	response = await client.get(POW_PATH, params={'purpose': 'login'})
	challenge = _json(response)
	cid = challenge.get('id')
	prefix = challenge.get('prefix')
	difficulty = challenge.get('difficulty')
	if not (isinstance(cid, str) and isinstance(prefix, str)
	        and isinstance(difficulty, int) and 1 <= difficulty <= 32):
		return None, f'取 PoW 挑战失败: {_error_of(response, challenge)}'

	nonce = await asyncio.to_thread(
		_solve_pow, cid, prefix, challenge.get('salt'), difficulty,
		str(challenge.get('purpose') or 'login'), int(challenge.get('epoch') or 0),
	)
	if nonce is None:
		return None, f'PoW 求解超时（难度 {difficulty}）'

	fp, machine = _fingerprint_for(login.username or '')
	response = await client.post(LOGIN_PATH, json={
		'email': login.username,
		'password': login.password,
		'csrfToken': csrf,
		'powId': cid,
		'powNonce': nonce,
		'fingerprint': fp,
		'fpVersion': '2026',
		'machineId': machine,
	})
	body = _json(response)
	if response.status_code != 200 or not body.get('token'):
		return None, _error_of(response, body)

	# 登录后 jar 里会有两条 `session`：客户端手工种进来的旧会话（domain=''，多半已过期），
	# 和服务端 Set-Cookie 下发的新会话（domain=站点主机名）。`client.cookies.jar` 不保证顺序，
	# 取第一条会随机撞上那条过期的空域 cookie —— 实测就是这样把一次成功登录读成 401 的。
	# 只认服务端按本域下发的新 cookie，取不到就用响应里的 token 兜底（二者同值）。
	cookie = None
	host = urlparse(login.base_url).hostname or ''
	for c in client.cookies.jar:
		domain = (c.domain or '').lstrip('.')
		if c.name == 'session' and domain and host and (domain == host or host.endswith('.' + domain)):
			cookie = c.value
			break
	# token 与 cookie 同值；某个环节没写进 jar 时用它兜底，别让一次成功登录白费。
	return cookie or str(body['token']), None


# ─────────────────────────── 签到 ─────────────────────────────
async def _balance(client: httpx.AsyncClient) -> Optional[float]:
	"""站点自己的余额数字（credits，不是 New API 的 quota 原值）。"""
	try:
		body = _json(await client.get(BALANCE_PATH))
	except Exception:
		return None
	value = body.get('totalBalance')
	return round(float(value), 2) if isinstance(value, (int, float)) else None


async def check_in(login: Login, site: Optional[SiteInfo] = None) -> Outcome:
	"""签到。已有会话先直用，401 再补一次登录（PoW 只要连上就必然能过）。"""
	base_url = login.base_url
	async with _client(base_url, session=login.session) as client:
		response = await client.get(DAILY_REWARD_PATH)
		if response.status_code == 401 or not _json(response):
			# 会话过期（`invalid_session`）或根本没存 -> 重新登录拿一张
			session, error = await _login(client, login)
			if error or not session:
				return Outcome(False, error=f'登录失败: {error}', session=login.session)
			# 只保留这次登录确认有效的那一条会话。重登后 jar 里会同时留着客户端手工种的
			# 过期空域旧 cookie，若一起发出去，服务端取哪条不确定 —— 绑到站点域名再 set，
			# 正好替换服务端刚下发的本域 cookie，只带新会话。
			host = urlparse(base_url).hostname or ''
			client.cookies.clear()
			if host:
				client.cookies.set('session', session, domain=host)
			else:
				client.cookies.set('session', session)
			response = await client.get(DAILY_REWARD_PATH)
		status = _json(response)
		if response.status_code != 200 or not status:
			return Outcome(False, error=f'读取签到状态失败: {_error_of(response, status)}')

		session = next((c.value for c in client.cookies.jar if c.name == 'session'), None) or login.session
		before = await _balance(client)
		# `canClaim` 是站点自己的判断，比本地时钟可靠（本机时钟被桩化过，
		# 用 lastClaim 跟本地日期比会误判）。
		if not status.get('canClaim'):
			return Outcome(
				True, checked_in=False,
				before_quota=before, after_quota=before,
				session=session,
			)
		reward = status.get('rewardAmount')

		response = await client.post(CLAIM_PATH)
		body = _json(response)
		after = await _balance(client)
		if response.status_code != 200:
			message = _error_of(response, body)
			if ALREADY_DONE.search(message):
				return Outcome(True, checked_in=False, before_quota=before,
				               after_quota=after or before, session=session)
			return Outcome(False, error=f'领取失败: {message}', before_quota=before,
			               after_quota=after, session=session)
		return Outcome(
			True, checked_in=True,
			before_quota=before, after_quota=after,
			session=session,
			awarded=float(reward) if isinstance(reward, (int, float)) else None,
		)


async def looks_like_vyce(base_url: str) -> bool:
	"""这个站是不是自建后端那一类：`/user/daily-reward` 未登录回 401 JSON。

	用 401 而不是 200 判定，是因为未登录就该是 401；New API 系这个路径要么 404、
	要么被 WAF 换成 HTML（那两种情况都不是 JSON），都不会误判。
	"""
	try:
		async with _client(base_url) as client:
			response = await client.get(DAILY_REWARD_PATH)
	except Exception:
		return False
	if response.status_code != 401:
		return False
	if 'json' not in response.headers.get('content-type', ''):
		return False
	body = _json(response)
	err = body.get('error')
	code = err.get('code') if isinstance(err, dict) else body.get('code')
	return code in ('not_authenticated', 'invalid_session') or bool(body.get('error'))
