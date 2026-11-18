"""Captcha failures are actionable without exposing provider data or answers."""
import httpx
import pytest

from panel import captcha, newapi


@pytest.fixture
def captcha_site(monkeypatch):
	monkeypatch.setenv('CHECKIN_VISION_BASE_URL', 'https://vision.test/v1')
	monkeypatch.setenv('CHECKIN_VISION_API_KEY', 'private-api-key')
	monkeypatch.setenv('CHECKIN_DEBUG', '1')
	real_client = httpx.AsyncClient
	provider = {'response': httpx.Response(401, json={'error': {'message': 'Authorization private-api-key provider-private'}})}

	def vision(request):
		if isinstance(provider['response'], Exception):
			raise provider['response']
		return provider['response']

	def client(**kwargs):
		kwargs.setdefault('transport', httpx.MockTransport(vision))
		return real_client(**kwargs)

	def site(request):
		if request.url.path == '/api/user/self':
			return httpx.Response(200, json={'success': True, 'data': {'quota': 500000}})
		if request.url.path.endswith('/captcha'):
			return httpx.Response(200, json={'success': True, 'data': {'captcha_id': 'id', 'captcha_image': 'base64-image'}})
		return httpx.Response(200, json={'success': False, 'message': '请输入验证码'})

	monkeypatch.setattr(captcha.httpx, 'AsyncClient', client)
	monkeypatch.setattr(newapi, '_client', lambda base_url, **kw: real_client(base_url=base_url, transport=httpx.MockTransport(site)))
	provider['site_handler'] = site
	provider['client'] = real_client
	return provider


@pytest.mark.parametrize('response, summary', [
	(httpx.Response(401, json={'error': 'Authorization private-api-key provider-private'}), 'HTTP 401'),
	(httpx.Response(400, json={'error': 'provider-private'}), 'HTTP 400'),
	(httpx.ReadTimeout('Authorization private-api-key provider-private'), '请求超时'),
	(httpx.ConnectError('private-api-key provider-private'), '连接失败'),
	(httpx.Response(200, json={'choices': [{'message': {'content': ''}}]}), '未返回可用内容'),
	(httpx.Response(200, text='provider-private'), '响应无法解析'),
])
async def test_provider_http_failure_reaches_outcome_without_secrets(captcha_site, capsys, response, summary):
	captcha_site['response'] = response
	outcome = await newapi.check_in(
		newapi.Login(base_url='https://site.test', session='s'),
		newapi.SiteInfo(base_url='https://site.test', checkin_path='/api/user/checkin'),
	)
	assert not outcome.success
	assert '验证码识别失败' in outcome.error
	assert summary in outcome.error
	captured = capsys.readouterr()
	for secret in ('private-api-key', 'provider-private', 'Authorization'):
		assert secret not in outcome.error + captured.out + captured.err

async def test_wrong_answers_are_retried_without_logging_answers(captcha_site, monkeypatch, capsys):
	captcha_site['response'] = httpx.Response(200, json={'choices': [{'message': {'content': 'AB123'}}]})
	attempts = []
	def site(request):
		if request.url.path == '/api/user/checkin':
			attempts.append(request.content)
			return httpx.Response(200, json={'success': False, 'message': '验证码错误'})
		return captcha_site['site_handler'](request)
	monkeypatch.setattr(newapi, '_client', lambda base_url, **kw: captcha_site['client'](base_url=base_url, transport=httpx.MockTransport(site)))
	outcome = await newapi.check_in(newapi.Login(base_url='https://site.test', session='s'), newapi.SiteInfo(base_url='https://site.test', checkin_path='/api/user/checkin'))
	assert not outcome.success
	assert len(attempts) == 1 + newapi.CAPTCHA_ATTEMPTS
	assert b'AB123' in attempts[-1]
	captured = capsys.readouterr()
	assert 'AB123' not in captured.out + captured.err + outcome.error


async def test_solver_compatibility_returns_clean_answer(captcha_site):
	captcha_site['response'] = httpx.Response(200, json={'choices': [{'message': {'content': 'AB123'}}]})
	assert await captcha.solve_image('base64-image') == 'AB123'
