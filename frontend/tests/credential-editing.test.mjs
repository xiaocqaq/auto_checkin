import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source.replace('import.meta.env.BASE_URL', JSON.stringify('/')), { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
const api = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'))
const form = readFileSync(new URL('../src/AccountForm.tsx', import.meta.url), 'utf8')
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8')

test('empty editing inputs omit secrets while explicit clearing sends null', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(api.credentialPatch({ password: '', session: '', access_token: '' }, []))), {})
  assert.deepEqual(api.credentialPatch({ password: '', session: 'new-cookie', access_token: '' }, ['password']),
    { password: null, session: 'new-cookie' })
})

test('editing and status display depend only on presence flags', () => {
  assert.doesNotMatch(form, /account\?\.(password|session|access_token)\b/)
  assert.doesNotMatch(app, /acc\.(password|session|access_token)\b/)
  assert.match(form, /credentialPatch/)
  assert.match(form, /清除已存/)
})
