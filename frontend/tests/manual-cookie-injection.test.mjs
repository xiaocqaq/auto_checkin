import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8')
const modal = readFileSync(new URL('../src/IdpCookiesModal.tsx', import.meta.url), 'utf8')
const api = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')

test('the frontend has no automatic browser-extension import path', () => {
  assert.doesNotMatch(app, /importFromBrowser|onBrowserImport|github-import|checkin-panel-extension|idpTransfer/i)
  assert.doesNotMatch(modal, /onBrowserImport|从当前浏览器导入|扩展/i)
  assert.doesNotMatch(api, /beginIdpTransfer|idpTransferJob|completeIdpTransfer|idp-transfer/i)
})

test('manual IdP cookie injection remains available for GitHub and other providers', () => {
  assert.match(modal, /导出的 cookie JSON/)
  assert.match(modal, /请仅粘贴对应登录平台导出的 Cookie JSON，不要包含其他网站会话/)
  assert.doesNotMatch(modal, /面板自己挑出要用的那几条/)
  assert.match(modal, /onValueChange=\{setCookies\}/)
  assert.match(modal, /api\.injectIdpCookies\(account\.id, cookies, verify\)/)
  assert.match(api, /idp-cookies/)
  assert.match(app, /onInjected=\{\(acc, result\) => void afterInjected\(acc, result\)\}/)
})
