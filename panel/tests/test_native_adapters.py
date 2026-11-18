"""Native daily-reward contracts against MockTransport; no browser or live network."""
import json

import httpx
import pytest

from panel import sub2api, vyce
from panel.newapi import Login


SITE = 'https://native.test'


@pytest.fixture
def wire_transport(monkeypatch):
	"""Keep each adapter's real headers/cookies; replace only HTTP transport."""
	real_client = httpx.AsyncClient

	def wire(handler):
		def client(*args, **kwargs):
			kwargs['transport'] = httpx.MockTransport(handler)
			kwargs['proxy'] = None
			kwargs['trust_env'] = False
			return real_client(*args, **kwargs)
		monkeypatch.setattr(httpx, 'AsyncClient', client)

	return wire


@pytest.mark.parametrize('already_claimed', [True, False], ids=['already-today-no-post', 'claim-updates-balance'])
async def test_vyce_daily_reward_uses_native_status_and_balance(wire_transport, already_claimed):
	requests = []
	balance = 12.50
	claimed = already_claimed

	def handler(request):
		nonlocal balance, claimed
		assert request.url.host == 'native.test'
		assert request.headers['cookie'] == 'session=test-session'
		assert request.headers['origin'] == SITE
		step = (request.method, request.url.path)
		requests.append(step)
		if step == ('GET', '/user/daily-reward'):
			return httpx.Response(200, json={'canClaim': not claimed, 'rewardAmount': 2.25})
		if step == ('GET', '/user/balance'):
			return httpx.Response(200, json={'totalBalance': balance})
		if step == ('POST', '/user/daily-reward/claim'):
			assert not claimed, 'must not claim again after the server says today is done'
			assert request.content == b''
			claimed = True
			balance += 2.25
			return httpx.Response(200, json={'success': True})
		raise AssertionError(f'unexpected native request: {step}')

	wire_transport(handler)
	result = await vyce.check_in(Login(base_url=SITE, session='test-session'))

	assert result.success is True
	assert result.checked_in is (not already_claimed)
	assert result.error is None
	assert result.session == 'test-session'
	assert result.before_quota == 12.50
	assert result.after_quota == (12.50 if already_claimed else 14.75)
	assert result.delta == (0.0 if already_claimed else 2.25)
	assert result.awarded == (None if already_claimed else 2.25)
	expected = [('GET', '/user/daily-reward'), ('GET', '/user/balance')]
	if not already_claimed:
		expected += [('POST', '/user/daily-reward/claim'), ('GET', '/user/balance')]
	assert requests == expected


@pytest.mark.parametrize('already_claimed', [True, False], ids=['already-today-no-post', 'claim-updates-balance'])
async def test_sub2api_checkin_uses_native_status_and_balance(wire_transport, already_claimed):
	requests = []
	balance = 8.25
	claimed = already_claimed

	def handler(request):
		nonlocal balance, claimed
		assert request.url.host == 'native.test'
		assert request.headers['authorization'] == 'Bearer test-access'
		assert request.headers['x-user-ui-request'] == '1'
		step = (request.method, request.url.path)
		requests.append(step)
		if step == ('GET', '/api/v1/check-in/status'):
			return httpx.Response(200, json={'data': {
				'enabled': True, 'checked_in_today': claimed, 'turnstile_required': False,
				'free_balance': balance, 'today_reward': 1.50 if claimed else 0, 'user_id': 7,
			}})
		if step == ('POST', '/api/v1/check-in'):
			assert not claimed, 'must not claim again after the server says today is done'
			assert json.loads(request.content) == {'turnstile_token': ''}
			claimed = True
			balance += 1.50
			# The fresh balance must come from the follow-up status, not a fabricated POST value.
			return httpx.Response(200, json={'data': {'reward_amount': 1.50}})
		raise AssertionError(f'unexpected native request: {step}')

	wire_transport(handler)
	result = await sub2api.check_in(Login(base_url=SITE, access_token='test-access', session='test-refresh'))

	assert result.success is True
	assert result.checked_in is (not already_claimed)
	assert result.error is None
	assert result.session == 'test-refresh'
	assert result.access_token == 'test-access'
	assert result.before_quota == 8.25
	assert result.after_quota == (8.25 if already_claimed else 9.75)
	assert result.delta == (0.0 if already_claimed else 1.50)
	assert result.awarded == (None if already_claimed else 1.50)
	expected = [('GET', '/api/v1/check-in/status')]
	if not already_claimed:
		expected += [('POST', '/api/v1/check-in'), ('GET', '/api/v1/check-in/status')]
	else:
		assert result.api_user == '7'
	assert requests == expected
