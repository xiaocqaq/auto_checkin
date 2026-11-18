"""Import and check-in must share occupancy without recording a false failure."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from panel.browser_login import IdpInjection
from panel.service import CheckInService
from panel.store import AccountStore


@pytest.mark.asyncio
async def test_import_blocks_checkin_without_increasing_failure_count(tmp_path, monkeypatch):
    import panel.browser_login as module
    store = AccountStore(tmp_path / 'panel.db')
    account = store.create(name='A', base_url='https://x.test', login_method='github')
    service = CheckInService(store)
    started, finish = asyncio.Event(), asyncio.Event()
    async def inject(*args, **kwargs):
        started.set()
        await finish.wait()
        return IdpInjection(injected=1, hosts=('github.com',), verified=None)
    monkeypatch.setattr(module, 'inject_idp_cookies', inject)
    service._attempt = AsyncMock(side_effect=RuntimeError('must not launch while importing'))
    task = asyncio.create_task(service.inject_idp_cookies(account.id, '[]', verify=False))
    await started.wait()
    try:
        outcome = await service.check_in(account.id)
        service._attempt.assert_not_called()
        assert not outcome.success and '正在' in outcome.error
        assert store.get(account.id).failures == 0
        assert store.get(account.id).last_run_at is None
    finally:
        finish.set()
        await task


@pytest.mark.asyncio
async def test_checkin_keeps_occupancy_through_reconciliation_and_storage(tmp_path, monkeypatch):
    from panel import newapi
    from panel.vendor.utils.browser import ProfileBusyError
    import panel.browser_login as module
    store = AccountStore(tmp_path / 'panel.db')
    account = store.create(name='A', base_url='https://x.test', login_method='github')
    service = CheckInService(store)
    reconciling, release = asyncio.Event(), asyncio.Event()
    async def reconcile(*args):
        reconciling.set()
        await release.wait()
    service._attempt = AsyncMock(return_value=(newapi.Outcome(True, session='old-run'), None))
    service._reconcile = reconcile
    inject = AsyncMock(return_value=IdpInjection(1, ('github.com',), verified=True, credential='fresh-import'))
    monkeypatch.setattr(module, 'inject_idp_cookies', inject)
    task = asyncio.create_task(service.check_in(account.id))
    await reconciling.wait()
    try:
        with pytest.raises(ProfileBusyError):
            await service.inject_idp_cookies(account.id, '[]')
        inject.assert_not_called()
    finally:
        release.set()
        await task
    assert account.id not in service._running
    await service.inject_idp_cookies(account.id, '[]')
    assert store.get(account.id).session == 'fresh-import'
