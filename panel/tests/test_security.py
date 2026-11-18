"""Security boundaries exercised through real HTTP routes and a real temporary store."""
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from panel.app import create_app
from panel.service import CredentialCheck
from panel.store import AccountStore


@pytest.fixture
def setup(tmp_path):
    store = AccountStore(tmp_path / 'accounts.db')
    service = MagicMock()
    service.verify_credential = AsyncMock(return_value=CredentialCheck(True))
    client = TestClient(create_app(store=store, service=service), base_url='http://127.0.0.1')
    return store, service, client


def test_account_read_and_write_responses_never_return_credentials(setup):
    store, service, client = setup
    secrets = dict(password='private-password', session='private-cookie', access_token='private-token')
    created = client.post('/api/accounts', json=dict(name='A', base_url='https://site.test', **secrets))
    assert created.status_code == 201
    account_id = created.json()['account']['id']
    updated = client.put(f'/api/accounts/{account_id}', json={'name': 'Renamed'})
    bodies = [created.json()['account'], updated.json()['account'],
              client.get(f'/api/accounts/{account_id}').json(), client.get('/api/accounts').json()[0]]
    for body in bodies:
        for name in secrets:
            assert name not in body
            assert body[f'has_{name}'] is True
    assert store.get(account_id).session == secrets['session']


def test_explicit_null_clears_only_the_selected_credential(setup):
    store, service, client = setup
    account = store.create(name='A', base_url='https://site.test', password='pw', session='cookie', access_token='token')
    response = client.put(f'/api/accounts/{account.id}', json={'session': None})
    assert response.status_code == 200
    saved = store.get(account.id)
    assert not saved.session
    assert saved.password == 'pw' and saved.access_token == 'token'
    assert response.json()['account']['has_session'] is False
    service.verify_credential.assert_not_called()


@pytest.mark.parametrize('headers', [
    {'origin': 'https://evil.test'},
    {'origin': 'null'},
    {'sec-fetch-site': 'cross-site'},
    {'origin': 'https://evil.test', 'x-forwarded-host': 'evil.test', 'x-forwarded-proto': 'https'},
])
def test_cross_site_bodyless_write_is_rejected_before_side_effects(setup, headers):
    store, service, client = setup
    account = store.create(name='A', base_url='https://site.test')
    service.bootstrap = AsyncMock(return_value='user')
    response = client.post(f'/api/accounts/{account.id}/bootstrap', headers=headers)
    assert response.status_code == 403
    service.bootstrap.assert_not_called()


def test_untrusted_host_is_rejected_even_without_origin(setup):
    _, _, client = setup
    assert client.get('/api/accounts', headers={'host': 'evil.test'}).status_code == 400


@pytest.mark.parametrize('base_url', ['http://127.0.0.1:49152', 'http://localhost:55001', 'http://[::1]:49153'])
def test_desktop_random_ports_accept_same_origin(setup, base_url):
    _, _, client = setup
    response = client.post(base_url + '/api/accounts', headers={'origin': base_url},
                           json={'name': 'A', 'base_url': 'https://site.test'})
    assert response.status_code == 201


def test_explicit_proxy_origin_works_without_trusting_forwarded_host(setup, monkeypatch):
    store, service, _ = setup
    monkeypatch.setenv('PANEL_ALLOWED_ORIGINS', 'https://panel.example')
    client = TestClient(create_app(store=store, service=service), base_url='http://127.0.0.1:8000')
    response = client.post('/api/accounts', headers={'origin': 'https://panel.example'},
                           json={'name': 'A', 'base_url': 'https://site.test'})
    assert response.status_code == 201
    assert client.get('/api/accounts', headers={'host': 'panel.example'}).status_code == 200


def test_console_launcher_defaults_to_loopback(monkeypatch):
    import ast
    import os
    from pathlib import Path
    from types import SimpleNamespace
    monkeypatch.delenv('PANEL_HOST', raising=False)
    main = next(node for node in ast.parse(Path('run.py').read_text()).body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    uvicorn = SimpleNamespace(run=MagicMock())
    scope = dict(os=os, uvicorn=uvicorn, AccountStore=MagicMock(), create_app=MagicMock(),
                 CheckInService=MagicMock(), _SANDBOX=SimpleNamespace(db_path='unused', dist_dir=None, loopback_patched=False))
    exec(compile(ast.Module(body=[main], type_ignores=[]), 'run.py', 'exec'), scope)
    scope['main']()
    assert uvicorn.run.call_args.kwargs['host'] == '127.0.0.1'


@pytest.mark.parametrize('credential, token', [('', 'Bearer fresh-token'), ('fresh-cookie', None)])
def test_browser_login_persists_new_token_or_retires_old_token(setup, monkeypatch, credential, token):
    import sys
    from types import SimpleNamespace
    store, _, client = setup
    account = store.create(name='A', base_url='https://site.test', login_method='github', access_token='old-token')
    login = AsyncMock(return_value=SimpleNamespace(credential=credential, access_token=token, user={'id': '7'}))
    monkeypatch.setitem(sys.modules, 'panel.browser_login', SimpleNamespace(browser_login=login))
    response = client.post(f'/api/accounts/{account.id}/browser-login', json={'set_password': False})
    assert response.status_code == 200
    saved = store.get(account.id)
    assert saved.access_token == (token or '')
    assert 'fresh-token' not in response.text


def test_idp_injection_never_returns_new_bearer_token(setup):
    from panel.browser_login import IdpInjection
    store, service, client = setup
    account = store.create(name='A', base_url='https://site.test', login_method='github')
    service.inject_idp_cookies = AsyncMock(return_value=IdpInjection(
        injected=1, hosts=('github.com',), verified=True, access_token='Bearer private-token'))
    response = client.post(f'/api/accounts/{account.id}/idp-cookies', json={'cookies': '[]'})
    assert response.status_code == 200
    assert 'access_token' not in response.json()
    assert 'private-token' not in response.text
