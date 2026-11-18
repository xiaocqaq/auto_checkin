"""Credential lifetime across optional reconciliation and browser retries."""
from types import SimpleNamespace

import pytest

from panel import browser_login, newapi
from panel.service import CheckInService
from panel.store import AccountStore


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path / 'accounts.db')


async def test_reconciliation_failure_does_not_lose_fresh_credentials(store, monkeypatch):
    service = CheckInService(store)
    account = store.create(name='rotation', base_url='https://example.test', access_token='expired', session='spent')

    async def attempt(_):
        return newapi.Outcome(True, access_token='fresh', session='rotated'), newapi.SiteInfo(base_url=account.base_url)

    async def reconcile(*_):
        raise RuntimeError('unrecognised reconciliation response')

    monkeypatch.setattr(service, '_attempt', attempt)
    monkeypatch.setattr(service, '_reconcile', reconcile)
    try:
        await service.check_in(account.id)
    except RuntimeError:
        pass  # Check persistence first; the optional read-back must not escape either.
    saved = store.get(account.id)
    assert saved.access_token == 'fresh'
    assert saved.session == 'rotated'
    assert saved.last_success is True
    assert account.id not in service._running


async def test_browser_cleared_token_is_not_resurrected_for_reconciliation(store, monkeypatch):
    service = CheckInService(store)
    account = store.create(name='browser', base_url='https://example.test', login_method='github', access_token='expired')
    site = newapi.SiteInfo(base_url=account.base_url, checkin_path='/api/user/checkin')
    seen = []

    async def login(**_):
        return SimpleNamespace(credential='fresh-cookie', user={'id': 7}, access_token=None)

    async def balance(*_, **__):
        return 1.0

    async def check_in(login, site):
        assert login.access_token is None
        return newapi.Outcome(True, session=login.session)

    async def last_checkin(*_, **credentials):
        seen.append(credentials)
        return None

    async def attempt(account):
        return await service._browser_check_in(account, site), site

    monkeypatch.setattr(browser_login, 'browser_login', login)
    monkeypatch.setattr(newapi, 'balance', balance)
    monkeypatch.setattr(newapi, 'check_in', check_in)
    monkeypatch.setattr(newapi, 'last_checkin_at', last_checkin)
    monkeypatch.setattr(service, '_attempt', attempt)
    await service.check_in(account.id)
    assert not store.get(account.id).access_token
    assert seen[0]['session'] == 'fresh-cookie'
    assert not seen[0]['access_token']


async def test_turnstile_retry_carries_newly_won_access_token(store, monkeypatch):
    service = CheckInService(store)
    account = store.create(name='turnstile', base_url='https://example.test', access_token='expired', session='spent')
    site = newapi.SiteInfo(base_url=account.base_url, checkin_path='/api/user/checkin', turnstile_key='sitekey')
    seen = []

    async def mint(**_):
        return 'challenge-proof'

    async def check_in(login, site):
        seen.append(login)
        return newapi.Outcome(True)

    monkeypatch.setattr(browser_login, 'mint_turnstile', mint)
    monkeypatch.setattr(newapi, 'check_in', check_in)
    await service._with_turnstile(
        account, site, service._login(account),
        newapi.Outcome(False, session='rotated', access_token='fresh-token'),
    )
    assert seen[0].session == 'rotated'
    assert seen[0].access_token == 'fresh-token'
    assert seen[0].turnstile == 'challenge-proof'
