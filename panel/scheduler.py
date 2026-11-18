"""Daily scheduler — while the panel is running it checks in by itself.

One successful check-in per account per window (ADR-0011), and nothing more: an
account that already collected is skipped until its next window opens. A failure is
retried, but with a widening gap — 30min, 1h, 2h, 4h — because a site that has
nothing to give at 09:00 rarely has something at 09:30, and every retry costs a
browser launch.
"""
import asyncio
import time
from datetime import datetime
from typing import Optional

from panel.service import CheckInService, _today_start, attempt_gate
from panel.store import Account, AccountStore

# ponytail: fixed poll interval, no cron expressions. A per-site window lives on the
# account (`checkin_after`, ADR-0011); this is only how often the loop looks.
TICK_S = 30 * 60
MAX_BACKOFF_S = 4 * 60 * 60  # a site that has failed all morning is not fixed by asking faster


def backoff_s(failures: int) -> float:
	"""How long to leave a failing account alone: 30min, 1h, 2h, then 4h.

	An account that cannot check in today usually cannot check in for hours (a dead
	credential, a WAF, a site with nothing to give), and each retry costs a browser
	launch. Success resets the count, and a new window ignores the backoff entirely.
	"""
	return min(TICK_S * 2 ** max(0, failures - 1), MAX_BACKOFF_S)


def due(account: Account, now: Optional[datetime] = None) -> bool:
	"""Enabled, past its start time today, and not yet succeeded today.

	Two different questions, deliberately kept apart (本机 修正):
	  * 「今天什么时候可以动手」= `attempt_gate()`：`checkin_after` 落到今天的那个时刻，
    不跨天回滚。设 09:10 就绝不在 09:10 之前动它 —— 上游的 `window_start` 会把凌晨
    算成「昨天的窗口」，导致面板每天凌晨抢跑，用户设置形同废纸（实测 relay18）。
	  * 「今天成功过没有」= 上次运行是否发生在今天 0 点之后。
	"""
	if not (account.enabled and account.base_url):
		return False
	if not (account.has_password or account.access_token or account.session):
		return False
	now = now or datetime.now().astimezone()
	# 还没到今天的启动时刻：等。这一条就是用户设置生效的地方。
	if now.timestamp() < attempt_gate(account, now):
		return False
	if not account.last_run_at:
		return True
	try:
		ran_at = datetime.fromisoformat(account.last_run_at).timestamp()
	except ValueError:
		return True
	if account.last_success and ran_at >= _today_start(now):
		return False  # 今天已经签成功了，收工
	if account.last_success:
		return True  # 上次成功是昨天的 -> 今天还没签
	return time.time() - ran_at >= backoff_s(account.failures)


async def run_once(store: AccountStore, service: CheckInService) -> dict:
	account_ids = [a.id for a in store.list_enabled() if due(a)]
	if not account_ids:
		return {}
	results = await service.check_in_many(account_ids)
	for account_id, outcome in results.items():
		state = 'OK' if outcome.success else 'FAIL'
		print(
			f'[SCHED] #{account_id} {state} checked_in={outcome.checked_in} '
			f'quota={outcome.after_quota} {outcome.error or ""}'.rstrip()
		)
	return results


async def loop(store: AccountStore, service: CheckInService, interval_s: int = TICK_S) -> None:
	while True:
		try:
			await run_once(store, service)
		except Exception as e:  # a scheduler that dies silently is worse than a noisy one
			print(f'[SCHED] tick failed: {type(e).__name__}: {e}')
		await asyncio.sleep(interval_s)
