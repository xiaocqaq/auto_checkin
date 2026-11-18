"""浏览器登录辅助函数"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .debug import debug_print, is_debug_enabled
from .popups import dismiss_popups, setup_popup_guard
from .proxy import get_playwright_proxy

if TYPE_CHECKING:
	from playwright.async_api import BrowserContext, Locator, Page

# 本机部署：给每个 profile 一个**固定**的指纹种子。
#
# 为什么要这层：cloakbrowser 默认每次启动都抽一个随机种子
# （config.py: `seed = random.randint(10000, 99999)`），于是同一个 profile 每次
# 打开都是「另一台设备」。GitHub 那类站点用「设备指纹 + 会话」判风险，指纹天天变
# 就让已登录的会话显得可疑（2026-10-03 实测同一出口 IP 从未变过，但 cli 里
# --fingerprint= 每次不同），轻则被要求重新验证，重则直接失效 —— 这就是「GitHub
# 登录存不住」的来源。种子的作用不是反检测强弱，而是让**同一 profile 前后一致**。
#
# 种子由 profile 路径稳定推导（不用 hash()：PYTHONHASHSEED 每进程随机，会自己毁掉
# 稳定性）。同一路径 → 同一指纹；换账号 → 换指纹，互不牵连。
_FINGERPRINT_MIN = 10000
_FINGERPRINT_RANGE = 90000  # randint(10000, 99999) 的区间，与 cloakbrowser 对齐


def _stable_fingerprint_seed(profile_dir) -> int:
	"""A per-profile fingerprint seed that does not change between launches."""
	import hashlib

	digest = hashlib.sha256(str(profile_dir).encode('utf-8')).hexdigest()
	return _FINGERPRINT_MIN + int(digest[:12], 16) % _FINGERPRINT_RANGE


def stealth_args_for(profile_dir) -> list[str]:
	"""Stable stealth args for `profile_dir` (overrides cloakbrowser's random seed)."""
	import platform as _platform

	args = ['--no-sandbox', f'--fingerprint={_stable_fingerprint_seed(profile_dir)}']
	if _platform.system() == 'Darwin':
		return args + ['--fingerprint-platform=macos']
	return args + ['--fingerprint-platform=windows']


def _pid_alive_in_this_container(pid: str) -> bool:
	"""Conservatively retain a lock unless its owner is confirmed absent."""
	try:
		raw = Path(f'/proc/{int(pid)}/cmdline').read_bytes()
	except FileNotFoundError:
		return False
	except (OSError, ValueError):
		return True  # unreadable/unknown is not proof that an owner exited
	return bool(raw)  # even a reused non-Chromium PID cannot be safely declared dead


def release_stale_profile_lock(profile_dir) -> list[str]:
	"""Remove a crash-left `Singleton*` lock so the next launch can start.

	本机部署：这是「又报错 Opening in existing browser session」的直接原因。

	Chromium 用 profile 目录里的 SingletonLock 记号把「这台机器上一次启动」记下来。
	浏览器**正常关闭**时会自己删掉；但被强杀 / 崩溃（`Target crashed`、容器 OOM、
	进程被杀）时它留着。于是下一次 `launch_persistent_context` 一看到锁，就认为
	「profile 正被另一台设备的进程占用」，启动直接失败 —— 而且是**永久**失败：
	除非人工删锁，否则这个账号的浏览器登录再也起不来。

	只删**确认已死**的锁：锁里写的是 `<主机名>-<pid>`，PID 在**本容器**里查不到活着的
	进程时才动手。这样同一 profile 真有两个并发启动时，第二个会老老实实报错，
	而不是把第一个正在用的锁删掉造成 profile 损坏。

	返回被清掉的锁文件名，便于调用方/日志追溯。
	"""
	import socket

	lock = Path(profile_dir) / 'SingletonLock'
	if not lock.is_symlink():
		return []
	try:
		target = os.readlink(lock)
	except OSError:
		return []
	holder, _, pid = target.rpartition('-')
	if holder != socket.gethostname():
		# 别的容器/机器写的锁，本进程没资格判断它死没死，别动。
		return []
	if not pid.isdigit() or _pid_alive_in_this_container(pid):
		return []
	removed = []
	for name in ('SingletonLock', 'SingletonSocket', 'SingletonCookie'):
		p = Path(profile_dir) / name
		try:
			if p.is_symlink() or p.exists():
				p.unlink()
				removed.append(name)
		except FileNotFoundError:
			pass
	if removed:
		print(f'[INFO] 清掉残留的浏览器 profile 锁 {lock.parent.name}: {", ".join(removed)}')
	return removed

EMAIL_LOGIN_BUTTON_NAMES = (
	re.compile(r'邮箱或用户名'),
	re.compile(r'使用.*邮箱'),
	re.compile(r'Email or Username', re.I),
	re.compile(r'Sign in with Email', re.I),
	re.compile(r'Sign in with Email or Username', re.I),
)
EMAIL_LOGIN_ENTRY_SELECTORS = (
	'.semi-card button:has(.semi-icon-mail):not(form.semi-form button)',
	'.semi-card button:has([aria-label="mail"]):not(form.semi-form button)',
	'.semi-card button.semi-button-primary:has(.semi-icon-mail)',
	'button:has(.semi-icon-mail):not(form.semi-form button)',
)
LOGIN_PAGE_READY_SELECTORS = (
	'.semi-card button:has(.semi-icon-mail)',
	'.semi-card',
	'button:has(.semi-icon-mail)',
)
LOGIN_FORM_SELECTOR = 'form.semi-form'
USERNAME_SELECTORS = ('#username', 'input[name="username"]', 'input[name="email"]', 'input[type="email"]')
PASSWORD_SELECTORS = ('#password', 'input[name="password"]', 'input[type="password"]')  # nosec B105
SUBMIT_SELECTORS = (
	f'{LOGIN_FORM_SELECTOR} button[type="submit"]',
	'button[type="submit"]',
)
SESSION_COOKIE_NAME = 'session'
USER_SELF_API_SUFFIX = '/api/user/self'
CONSOLE_PATH = '/console'
DEFAULT_SCREENSHOT_DIR = 'checkin_screenshots'
DEFAULT_TIMEOUT_MS = 60_000
_pending_notify_screenshots: list[Path] = []
FORM_ACTION_TIMEOUT_MS = 15_000
EMAIL_TAB_TIMEOUT_MS = 8_000
WAF_READY_TIMEOUT_MS = 30_000
SESSION_WAIT_TIMEOUT_MS = 45_000

_VISIBLE_CHECK_JS = """
	const isVisible = (el) => {
		if (!el || !el.isConnected) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
			return false;
		}
		const rect = el.getBoundingClientRect();
		return rect.width > 0 && rect.height > 0;
	};
	const countVisible = (selector) => [...document.querySelectorAll(selector)].filter(isVisible).length;
"""

_SITE_READY_JS = f"""() => {{
{_VISIBLE_CHECK_JS}
	const text = document.body?.innerText || '';
	const blocked = /请进行验证|为了更好的访问体验|访问受限|Access denied|verify you are human/i.test(text);
	if (blocked) return false;
	const wafBlockers = document.querySelector(
		'iframe[src*="captcha"], iframe[src*="verify"], iframe[src*="slide"], .nc-container, #nocaptcha'
	);
	if (wafBlockers) {{
		const rect = wafBlockers.getBoundingClientRect?.();
		if (rect && rect.width > 0 && rect.height > 0) return false;
	}}
	if (/\\/login/.test(location.pathname)) {{
		return countVisible('.semi-card') > 0 || countVisible('#username') > 0 || countVisible('button') >= 2;
	}}
	return countVisible('a') > 0 || countVisible('button') > 0;
}}"""

_LOGIN_SHELL_READY_JS = f"""() => {{
{_VISIBLE_CHECK_JS}
	const text = document.body?.innerText || '';
	const blocked = /请进行验证|为了更好的访问体验|访问受限|Access denied|verify you are human/i.test(text);
	if (blocked) return false;
	return countVisible('.semi-card') > 0 || countVisible('#username') > 0 || countVisible('button') >= 2;
}}"""

_OPEN_EMAIL_FORM_JS = """() => {
	const isVisible = (el) => {
		if (!el || !el.isConnected) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
			return false;
		}
		const rect = el.getBoundingClientRect();
		return rect.width > 0 && rect.height > 0;
	};

	const inDialog = (el) => !!el?.closest('[role="dialog"][aria-modal="true"], .semi-modal-content[role="dialog"]');

	const usernameSelectors = ['#username', 'input[name="username"]', 'input[name="email"]', 'input[type="email"]'];
	const findUsername = () => {
		for (const selector of usernameSelectors) {
			const el = document.querySelector(selector);
			if (isVisible(el)) return el;
		}
		return null;
	};

	if (findUsername()) return true;

	const entrySelectors = [
		'.semi-card button:has(.semi-icon-mail)',
		'.semi-card button:has([aria-label="mail"])',
	];
	for (const selector of entrySelectors) {
		for (const btn of document.querySelectorAll(selector)) {
			if (!isVisible(btn) || inDialog(btn) || btn.closest('form.semi-form')) continue;
			btn.click();
			if (findUsername()) return true;
		}
	}

	for (const tab of document.querySelectorAll('.semi-card .semi-tabs-tab')) {
		if (!isVisible(tab) || inDialog(tab)) continue;
		tab.click();
		if (findUsername()) return true;
	}

	return !!findUsername();
}"""


@dataclass(frozen=True)
class BrowserLoginResult:
	cookies: dict[str, str]
	api_user: str | None = None


@dataclass(frozen=True)
class BrowserLoginSettings:
	headless: bool
	humanize: bool
	wait_timeout_ms: int
	profile_dir: Path
	cloakbrowser_binary_path: str | None
	persist_profile: bool


def _env_bool(name: str, default: bool) -> bool:
	raw = os.getenv(name)
	if raw is None:
		return default
	return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


def load_browser_login_settings(
	account_name: str, provider: str, *, persist_profile: bool = True
) -> BrowserLoginSettings:
	profile_base = Path(os.getenv('CHECKIN_BROWSER_PROFILE_DIR', '.browser_profiles'))
	profile_dir = profile_base / provider / account_name
	humanize = _env_bool('CHECKIN_HUMANIZE', True)
	if provider == 'agentrouter':
		humanize = _env_bool('CHECKIN_HUMANIZE_AGENTROUTER', humanize)
	return BrowserLoginSettings(
		headless=_env_bool('CHECKIN_HEADLESS', True),
		humanize=humanize,
		wait_timeout_ms=int(os.getenv('CHECKIN_WAIT_TIMEOUT_MS', str(DEFAULT_TIMEOUT_MS))),
		profile_dir=profile_dir,
		cloakbrowser_binary_path=os.getenv('CLOAKBROWSER_BINARY_PATH', '').strip() or None,
		persist_profile=persist_profile,
	)


def _ensure_binary_path(settings: BrowserLoginSettings) -> None:
	if settings.cloakbrowser_binary_path:
		os.environ['CLOAKBROWSER_BINARY_PATH'] = settings.cloakbrowser_binary_path


class ProfileBusyError(RuntimeError):
	"""A profile is owned by another login, import, or check-in."""


_PROFILE_BUSY = '该账号的浏览器配置正在被登录、导入或签到使用，请等待当前操作结束后重试（不会清除 GitHub 会话）'


def _acquire_profile_lease(profile_dir, *, kind='browser'):
	"""Keep the stable lock inode outside the profile (forget_profile may delete it)."""
	import errno
	import hashlib
	try:
		import fcntl
	except ImportError:  # Windows has byte-range locks instead of flock.
		fcntl = None
		import msvcrt

	profile = Path(profile_dir).resolve()
	locks = profile.parent / '.profile-locks'
	locks.mkdir(parents=True, exist_ok=True)
	key = hashlib.sha256(str(profile).encode('utf-8')).hexdigest()
	lease = (locks / f'{key}.{kind}.lock').open('a+b')
	try:
		if fcntl is not None:
			fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
		else:
			# Windows permits locking beyond EOF; every holder locks the same first byte.
			# Closing the handle releases the lock on both platforms.
			lease.seek(0)
			msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
	except OSError as exc:
		lease.close()
		if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
			raise ProfileBusyError(_PROFILE_BUSY) from None
		raise
	except BaseException:
		lease.close()
		raise
	return lease


class _PersistentBrowserContext:
	def __init__(self, context: BrowserContext, lease) -> None:
		self._context = context
		self._lease = lease
		self._close_task = None

	def __getattr__(self, name: str):
		return getattr(self._context, name)

	async def _close(self, *args, **kwargs) -> None:
		try:
			await self._context.close(*args, **kwargs)
		except BaseException:
			print('[WARN] 浏览器关闭失败；仍存在的 Singleton 锁将继续阻止重复启动')
			raise
		finally:
			self._lease.close()

	async def close(self, *args, **kwargs) -> None:
		# Keep the lease until close finishes; a surviving Singleton still blocks relaunch.
		if self._close_task is None:
			self._close_task = asyncio.create_task(self._close(*args, **kwargs))
			self._close_task.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
		await asyncio.shield(self._close_task)


class _EphemeralBrowserContext:
	def __init__(self, context: BrowserContext, browser) -> None:
		self._context = context
		self._browser = browser

	def __getattr__(self, name: str):
		return getattr(self._context, name)

	async def close(self, *args, **kwargs) -> None:
		try:
			await self._context.close(*args, **kwargs)
		finally:
			await self._browser.close()


async def launch_login_context(settings: BrowserLoginSettings, *, use_proxy: bool = False) -> BrowserContext:
	_ensure_binary_path(settings)

	launch_kwargs: dict = {
		'headless': settings.headless,
		'humanize': settings.humanize,
		'viewport': {'width': 1920, 'height': 1080},
		# 本机部署：关掉 cloakbrowser 的随机指纹种子（stealth_args 是布尔开关，
		# 不是列表！），改用按 profile 稳定推导的固定种子，让同一账号每次都是
		# 「同一台设备」，登录/会话才存得住。见文件头注释。
		'stealth_args': False,
		'args': stealth_args_for(settings.profile_dir),
	}
	if settings.humanize:
		launch_kwargs['human_preset'] = 'careful'

	# 本机部署：CHECKIN_BROWSER_PROXY=1 时所有浏览器上下文走代理。本机在国内，
	# 被墙站点连页面都打不开，浏览器兜底（visit/重新登录/过盾）必须经 mihomo。
	# 上游默认只给 turnstile 一处开（use_proxy=True），这里按部署环境整体打开。
	if os.getenv('CHECKIN_BROWSER_PROXY', '').strip() == '1':
		use_proxy = True
	proxy = get_playwright_proxy(use_proxy=use_proxy)
	if proxy:
		launch_kwargs['proxy'] = proxy
		if is_debug_enabled():
			print(f'[INFO] Browser proxy enabled: {proxy["server"]}')
		else:
			print('[INFO] Browser proxy enabled')
	elif use_proxy:
		print('[WARN] Provider requires proxy but CHECKIN_PROXY_URL is not set')

	if settings.persist_profile:
		from cloakbrowser import launch_persistent_context_async

		lease = _acquire_profile_lease(settings.profile_dir)
		try:
			settings.profile_dir.mkdir(parents=True, exist_ok=True)
			release_stale_profile_lock(settings.profile_dir)
			# A visible/manual Chromium not started through this helper still owns its profile.
			lock = settings.profile_dir / 'SingletonLock'
			if os.path.lexists(lock):
				raise ProfileBusyError(_PROFILE_BUSY)
		except BaseException:
			lease.close()
			raise

		async def launch_owned():
			try:
				context = await launch_persistent_context_async(str(settings.profile_dir), **launch_kwargs)
			except BaseException:
				lease.close()
				raise
			return _PersistentBrowserContext(context, lease)

		launch_task = asyncio.create_task(launch_owned())
		try:
			return await asyncio.shield(launch_task)
		except asyncio.CancelledError:
			# Collect a context allocated during launch even if the request went away.
			async def cleanup():
				try:
					context = await launch_task
					await context.close()
				except BaseException:
					print('[WARN] 已取消请求的浏览器启动清理失败，请检查 Singleton owner')
			cleanup_task = asyncio.create_task(cleanup())
			await asyncio.shield(cleanup_task)
			raise

	from cloakbrowser import launch_async

	context_kwargs = {'viewport': launch_kwargs.pop('viewport')}
	browser = await launch_async(**launch_kwargs)
	context = await browser.new_context(**context_kwargs)
	return _EphemeralBrowserContext(context, browser)


def get_screenshot_dir() -> Path:
	return Path(os.getenv('CHECKIN_SCREENSHOT_DIR', DEFAULT_SCREENSHOT_DIR))


def _sanitize_screenshot_part(value: str) -> str:
	cleaned = re.sub(r'[^\w.-]+', '_', value.strip())
	return cleaned or 'unknown'


async def save_login_screenshot(
	page: Page,
	provider: str,
	account_name: str,
	label: str,
) -> Path | None:
	if not is_debug_enabled():
		return None

	screenshot_dir = get_screenshot_dir()
	screenshot_dir.mkdir(parents=True, exist_ok=True)
	timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
	filename = (
		f'{_sanitize_screenshot_part(provider)}_{_sanitize_screenshot_part(account_name)}'
		f'_{timestamp}_{_sanitize_screenshot_part(label)}.png'
	)
	path = screenshot_dir / filename
	try:
		await page.screenshot(path=str(path), full_page=True, timeout=15_000)
		_pending_notify_screenshots.append(path)
		print(f'[INFO] Screenshot saved: {path}')
		return path
	except Exception as exc:
		print(f'[WARN] Failed to save screenshot ({label}): {exc}')
		return None


def take_pending_screenshots() -> list[Path]:
	"""取出待推送的登录截图列表并清空缓存。"""
	paths = list(_pending_notify_screenshots)
	_pending_notify_screenshots.clear()
	return paths


async def prepare_browser_page(page: Page) -> None:
	await setup_popup_guard(page)


async def wait_for_site_ready(page: Page, timeout_ms: int = WAF_READY_TIMEOUT_MS) -> None:
	"""等待 WAF 通过并关闭弹窗。"""
	waf_timeout = min(timeout_ms, WAF_READY_TIMEOUT_MS)
	await page.wait_for_load_state('domcontentloaded', timeout=waf_timeout)
	try:
		await page.wait_for_function(_SITE_READY_JS, timeout=waf_timeout)
	except Exception:
		await asyncio.sleep(3)
	closed = await dismiss_popups(page)
	if closed:
		print(f'[INFO] Dismissed {closed} popup dialog(s)')


async def _wait_for_optional_load_state(page: Page, state: str, timeout_ms: int) -> bool:
	try:
		await page.wait_for_load_state(state, timeout=timeout_ms)
		return True
	except Exception as exc:  # nosec B110
		debug_print(f'[INFO] Optional load state "{state}" not reached within {timeout_ms}ms: {exc}')
		return False


async def _settle_page(page: Page, delay_seconds: float, networkidle_timeout_ms: int) -> None:
	await asyncio.sleep(delay_seconds)
	await _wait_for_optional_load_state(page, 'networkidle', networkidle_timeout_ms)


async def _wait_for_login_shell(page: Page, timeout_ms: int) -> bool:
	shell_timeout = min(timeout_ms, 60_000)
	try:
		await page.wait_for_function(_LOGIN_SHELL_READY_JS, timeout=shell_timeout)
		return True
	except Exception:  # nosec B110
		return False


async def navigate_login_page(
	page: Page,
	login_url: str,
	timeout_ms: int,
	*,
	provider: str = '',
	account_name: str = '',
) -> None:
	"""预热站点、导航登录页并等待 SPA 渲染完成。"""
	from urllib.parse import urlparse

	parsed = urlparse(login_url)
	base_url = f'{parsed.scheme}://{parsed.netloc}/'
	attempt_timeout = min(timeout_ms, 60_000)

	try:
		print(f'[INFO] Warming up {base_url} before login')
		await page.goto(base_url, wait_until='load', timeout=attempt_timeout)
		await _settle_page(page, 3, 15_000)
		closed = await dismiss_popups(page)
		if closed:
			print(f'[INFO] Dismissed {closed} popup dialog(s) during warmup')
	except Exception as exc:
		print(f'[WARN] Warmup navigation failed: {exc}')

	for attempt in range(3):
		print(f'[INFO] Navigating login page (attempt {attempt + 1}/3): {login_url}')
		await page.goto(login_url, wait_until='load', timeout=attempt_timeout)
		await _settle_page(page, 5, 20_000)

		if await _wait_for_login_shell(page, attempt_timeout):
			await wait_for_site_ready(page, timeout_ms)
			if await page.evaluate(_LOGIN_SHELL_READY_JS):
				return

		print(f'[WARN] Login page shell not ready on attempt {attempt + 1}')
		await _log_login_page_state(page)
		if provider and account_name:
			await save_login_screenshot(page, provider, account_name, f'login-shell-attempt-{attempt + 1}')
		if attempt < 2:
			await asyncio.sleep(5)
			try:
				await page.reload(wait_until='load', timeout=attempt_timeout)
			except Exception:  # nosec B110
				pass

	raise TimeoutError(f'Login page never rendered: {login_url}')


async def has_session_cookie(page: Page) -> bool:
	cookies = await page.context.cookies()
	return any(c.get('name') == SESSION_COOKIE_NAME and c.get('value') for c in cookies)


def _extract_user_profile(payload: object) -> dict | None:
	if not isinstance(payload, dict):
		return None
	data = payload.get('data')
	if payload.get('success') is True and isinstance(data, dict) and data.get('id'):
		return data
	if payload.get('id'):
		return payload
	return None


async def _parse_user_self_response(response) -> dict | None:
	if USER_SELF_API_SUFFIX not in response.url or response.status != 200:
		return None
	try:
		payload = await response.json()
	except Exception:  # nosec B110
		return None
	return _extract_user_profile(payload)


async def is_logged_in(page: Page) -> bool:
	"""快速判断：是否在 /console，或仍停留在登录页。"""
	url = page.url.lower()
	if CONSOLE_PATH in url:
		return True
	if '/login' in url or '/signin' in url or '/sign-in' in url:
		return False

	try:
		if await page.locator('.semi-card button:has(.semi-icon-mail)').first.is_visible():
			return False
	except Exception:  # nosec B110
		pass
	return False


async def wait_for_session_cookie(page: Page, timeout_ms: int = SESSION_WAIT_TIMEOUT_MS) -> bool:
	deadline = time.monotonic() + timeout_ms / 1000
	while time.monotonic() < deadline:
		if await has_session_cookie(page):
			return True
		await asyncio.sleep(0.5)
	return False


async def wait_for_logged_in(page: Page, timeout_ms: int = SESSION_WAIT_TIMEOUT_MS) -> bool:
	deadline = time.monotonic() + timeout_ms / 1000
	while time.monotonic() < deadline:
		if await is_logged_in(page):
			return True
		await asyncio.sleep(0.5)
	return False


async def verify_browser_login(page: Page, console_url: str, timeout_ms: int) -> dict | None:
	"""跳转 /console 并拦截 /api/user/self，用浏览器会话确认登录用户。"""
	verify_timeout = min(timeout_ms, SESSION_WAIT_TIMEOUT_MS)
	captured_profile: dict | None = None
	verified = asyncio.Event()

	async def on_response(response) -> None:
		nonlocal captured_profile
		if captured_profile is not None:
			return
		profile = await _parse_user_self_response(response)
		if profile:
			captured_profile = profile
			verified.set()

	page.on('response', on_response)
	try:
		print(f'[INFO] Verifying login via {console_url} and {USER_SELF_API_SUFFIX}')
		await page.goto(console_url, wait_until='load', timeout=min(timeout_ms, 60_000))
		try:
			await page.wait_for_load_state('networkidle', timeout=20_000)
		except Exception:  # nosec B110
			pass

		if captured_profile is None:
			try:
				await asyncio.wait_for(verified.wait(), timeout=verify_timeout / 1000)
			except TimeoutError:
				pass
	finally:
		page.remove_listener('response', on_response)

	if captured_profile:
		if is_debug_enabled():
			user_id = captured_profile.get('id')
			username = captured_profile.get('username', '')
			print(f'[INFO] Login verified via {USER_SELF_API_SUFFIX}: id={user_id}, username={username}')
		else:
			print('[INFO] Login verified')
		return captured_profile

	if CONSOLE_PATH in page.url.lower():
		print(f'[WARN] Reached {CONSOLE_PATH} but {USER_SELF_API_SUFFIX} returned no user profile')
	else:
		debug_print(f'[WARN] Login verification failed: current URL={page.url}')
		print('[WARN] Login verification failed')
	return None


async def wait_for_waf_ready(page: Page, timeout_ms: int = WAF_READY_TIMEOUT_MS) -> None:
	await wait_for_site_ready(page, timeout_ms)


async def _first_visible_locator(page: Page, selectors: tuple[str, ...]) -> Locator | None:
	for selector in selectors:
		locator = page.locator(selector).first
		try:
			if await locator.is_visible():
				return locator
		except Exception:  # nosec B112
			continue
	return None


async def _is_email_form_visible(page: Page) -> bool:
	return await _first_visible_locator(page, USERNAME_SELECTORS) is not None


async def _dismiss_blocking_overlays(page: Page) -> None:
	if await _is_email_form_visible(page):
		return
	for _ in range(3):
		closed = await dismiss_popups(page)
		if closed == 0:
			break
		await asyncio.sleep(0.3)


async def _click_locator(button: Locator) -> bool:
	try:
		await button.scroll_into_view_if_needed()
		await button.click(timeout=FORM_ACTION_TIMEOUT_MS)
		return True
	except Exception:
		try:
			await button.click(force=True, timeout=FORM_ACTION_TIMEOUT_MS)
			return True
		except Exception:  # nosec B112
			return False


async def _wait_for_login_page_ready(page: Page, timeout_ms: int) -> None:
	if await _is_email_form_visible(page):
		return

	remaining_ms = timeout_ms
	for selector in LOGIN_PAGE_READY_SELECTORS:
		if remaining_ms <= 0:
			break
		try:
			await page.locator(selector).first.wait_for(state='visible', timeout=remaining_ms)
			return
		except Exception:  # nosec B112
			continue

	for pattern in EMAIL_LOGIN_BUTTON_NAMES:
		if remaining_ms <= 0:
			break
		try:
			await page.get_by_role('button', name=pattern).first.wait_for(state='visible', timeout=remaining_ms)
			return
		except Exception:  # nosec B112
			continue


async def _click_email_login_entry(page: Page) -> bool:
	for selector in EMAIL_LOGIN_ENTRY_SELECTORS:
		buttons = page.locator(selector)
		button_count = await buttons.count()
		for index in range(button_count):
			button = buttons.nth(index)
			try:
				if await button.is_visible():
					if await _click_locator(button):
						return True
			except Exception:  # nosec B112
				continue

	for pattern in EMAIL_LOGIN_BUTTON_NAMES:
		for scope in (page.locator('.semi-card'), page):
			try:
				button = scope.get_by_role('button', name=pattern).first
				if await button.is_visible() and await _click_locator(button):
					return True
			except Exception:  # nosec B112
				continue

	return False


async def _wait_for_username_input(page: Page, timeout_ms: int) -> bool:
	if timeout_ms <= 0:
		return await _is_email_form_visible(page)

	for selector in USERNAME_SELECTORS:
		try:
			await page.locator(selector).first.wait_for(state='visible', timeout=timeout_ms)
			return True
		except Exception:  # nosec B112
			continue
	return False


async def _log_login_page_state(page: Page) -> None:
	state = await page.evaluate(
		"""() => {
			const isVisible = (el) => {
				if (!el || !el.isConnected) return false;
				const style = window.getComputedStyle(el);
				if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) return false;
				const rect = el.getBoundingClientRect();
				return rect.width > 0 && rect.height > 0;
			};
			const buttons = [...document.querySelectorAll('button')]
				.filter(isVisible)
				.map((b) => (b.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 60));
			return {
				title: document.title || '',
				readyState: document.readyState,
				bodySnippet: (document.body?.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 300),
				scriptCount: document.querySelectorAll('script').length,
				hasSemiCard: !!document.querySelector('.semi-card'),
				mailEntryCount: document.querySelectorAll('.semi-card button:has(.semi-icon-mail)').length,
				usernameVisible: isVisible(document.querySelector('#username')),
				modalVisible: [...document.querySelectorAll('div[role="dialog"][aria-modal="true"]')].some(isVisible),
				buttons: buttons.slice(0, 8),
			};
		}"""
	)
	debug_print(f'[INFO] Login page state: {state}')


async def _open_email_login_form(
	page: Page,
	timeout_ms: int,
	*,
	provider: str = '',
	account_name: str = '',
) -> None:
	deadline = time.monotonic() + timeout_ms / 1000

	await _dismiss_blocking_overlays(page)
	if await _is_email_form_visible(page):
		return

	ready_timeout = min(timeout_ms, WAF_READY_TIMEOUT_MS)
	try:
		await _wait_for_login_page_ready(page, ready_timeout)
	except Exception:  # nosec B110
		pass

	while time.monotonic() < deadline:
		remaining_ms = int((deadline - time.monotonic()) * 1000)
		if remaining_ms <= 0:
			break

		await _dismiss_blocking_overlays(page)
		if await _is_email_form_visible(page):
			return

		if await _click_email_login_entry(page):
			await asyncio.sleep(1)
			wait_ms = min(remaining_ms, FORM_ACTION_TIMEOUT_MS)
			if await _wait_for_username_input(page, wait_ms):
				return

		tabs = page.locator('.semi-card .semi-tabs-tab')
		tab_count = await tabs.count()
		for index in range(tab_count):
			tab = tabs.nth(index)
			if not await tab.is_visible():
				continue
			await tab.click(timeout=EMAIL_TAB_TIMEOUT_MS)
			wait_ms = min(int((deadline - time.monotonic()) * 1000), EMAIL_TAB_TIMEOUT_MS)
			if await _wait_for_username_input(page, wait_ms):
				return

		if await page.evaluate(_OPEN_EMAIL_FORM_JS):
			await asyncio.sleep(1)
			wait_ms = min(int((deadline - time.monotonic()) * 1000), FORM_ACTION_TIMEOUT_MS)
			if await _wait_for_username_input(page, wait_ms):
				return

		await asyncio.sleep(0.5)

	remaining_ms = int((deadline - time.monotonic()) * 1000)
	if remaining_ms > 0 and await _wait_for_username_input(page, remaining_ms):
		return

	debug_print(f'[INFO] Login page URL: {page.url}')
	await _log_login_page_state(page)
	if provider and account_name:
		await save_login_screenshot(page, provider, account_name, 'email-form-timeout')
	raise TimeoutError(f'Cannot open email login form, selectors: {USERNAME_SELECTORS}')


async def _set_input_value(locator: Locator, value: str, timeout_ms: int) -> None:
	click_timeout = min(timeout_ms, 5000)
	try:
		await locator.click(timeout=click_timeout)
	except Exception:
		try:
			await locator.click(force=True, timeout=click_timeout)
		except Exception:  # nosec B110
			pass

	try:
		await locator.fill(value, timeout=timeout_ms)
		if await locator.input_value(timeout=2000) == value:
			return
	except Exception:  # nosec B110
		pass

	await locator.evaluate(
		"""(el, v) => {
			const setter = Object.getOwnPropertyDescriptor(
				window.HTMLInputElement.prototype, 'value'
			)?.set;
			setter?.call(el, v);
			el.dispatchEvent(new Event('input', { bubbles: true }));
			el.dispatchEvent(new Event('change', { bubbles: true }));
		}""",
		value,
	)


async def fill_email_credentials(page: Page, email: str, password: str, timeout_ms: int) -> None:
	await _dismiss_blocking_overlays(page)
	action_timeout = min(timeout_ms, FORM_ACTION_TIMEOUT_MS)

	username_input = await _first_visible_locator(page, USERNAME_SELECTORS)
	if not username_input:
		for selector in USERNAME_SELECTORS:
			locator = page.locator(selector).first
			try:
				await locator.wait_for(state='visible', timeout=action_timeout)
				username_input = locator
				break
			except Exception:  # nosec B112
				continue
	if not username_input:
		raise TimeoutError(f'Cannot find username input: {USERNAME_SELECTORS}')

	password_input = await _first_visible_locator(page, PASSWORD_SELECTORS)
	if not password_input:
		for selector in PASSWORD_SELECTORS:
			locator = page.locator(selector).first
			try:
				await locator.wait_for(state='visible', timeout=action_timeout)
				password_input = locator
				break
			except Exception:  # nosec B112
				continue
	if not password_input:
		raise TimeoutError(f'Cannot find password input: {PASSWORD_SELECTORS}')

	await _set_input_value(username_input, email, action_timeout)
	await _set_input_value(password_input, password, action_timeout)


async def submit_login_form(page: Page, timeout_ms: int) -> None:
	action_timeout = min(timeout_ms, FORM_ACTION_TIMEOUT_MS)
	submit = await _first_visible_locator(page, SUBMIT_SELECTORS)
	if not submit:
		for selector in SUBMIT_SELECTORS:
			locator = page.locator(selector).first
			try:
				await locator.wait_for(state='visible', timeout=action_timeout)
				submit = locator
				break
			except Exception:  # nosec B112
				continue
	if not submit:
		raise TimeoutError(f'Cannot find submit button: {SUBMIT_SELECTORS}')
	try:
		await submit.click(timeout=action_timeout)
	except Exception:
		await submit.click(force=True, timeout=action_timeout)
	await _wait_for_optional_load_state(page, 'domcontentloaded', action_timeout)
	await _wait_for_optional_load_state(page, 'networkidle', min(timeout_ms, 30_000))
	await wait_for_logged_in(page, SESSION_WAIT_TIMEOUT_MS)


async def login_with_email_form(
	page: Page,
	email: str,
	password: str,
	timeout_ms: int,
	*,
	provider: str = '',
	account_name: str = '',
) -> None:
	await _open_email_login_form(
		page,
		timeout_ms,
		provider=provider,
		account_name=account_name,
	)
	await fill_email_credentials(page, email, password, timeout_ms)
	await submit_login_form(page, timeout_ms)
