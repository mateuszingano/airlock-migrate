// CLI-level tests: exit codes and gating. The unit tests cover the rules; these
// cover the contract CI actually consumes — what the process RETURNS. A rule that
// fires but can't change the exit code does not gate anything.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BIN = fileURLToPath(new URL('../bin/migration-guard.mjs', import.meta.url))

/** Run the CLI and return { code, stdout }. Never throws on non-zero exit. */
function run(args, env = {}) {
  try {
    const stdout = execFileSync(process.execPath, [BIN, ...args], {
      encoding: 'utf8',
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { code: 0, stdout }
  } catch (err) {
    return { code: err.status, stdout: `${err.stdout || ''}${err.stderr || ''}` }
  }
}

/** Write migrations into a throwaway dir. Returns the dir; caller removes it. */
function fixture(sql) {
  const dir = mkdtempSync(join(tmpdir(), 'mg-cli-'))
  mkdirSync(join(dir, 'm'), { recursive: true })
  writeFileSync(join(dir, 'm', '001.sql'), sql)
  return dir
}

const CLEAN_WITH_WARN = [
  'create table public.t (id int);',
  'alter table public.t enable row level security;',
  'create policy p on public.t for select to anon using (owner_id = auth.uid());',
  'drop trigger on_auth_user_created on auth.users;', // warn: dropped, never recreated
].join('\n')

const DANGEROUS = 'create table public.leaky (id int);\n'

test('exit codes: 0 clean, 1 dangerous, 2 usage', () => {
  const clean = fixture('create table public.t (id int);\nalter table public.t enable row level security;\n')
  const bad = fixture(DANGEROUS)
  try {
    assert.equal(run([join(clean, 'm')]).code, 0, 'clean → 0')
    assert.equal(run([join(bad, 'm')]).code, 1, 'dangerous → 1')
    assert.equal(run([join(clean, 'does-not-exist')]).code, 2, 'missing dir → 2')
    assert.equal(run([join(clean, 'm'), '--nope']).code, 2, 'unknown option → 2')
  } finally {
    rmSync(clean, { recursive: true, force: true })
    rmSync(bad, { recursive: true, force: true })
  }
})

// ONDA 0.3 — before this, the four warn-level rules could only ever be printed.
// `drop_trigger` in particular exists because a dropped signup trigger broke
// production once; a rule born from a real incident that cannot fail a build is
// decoration.
test('--fail-on warn lets warn-level rules gate the build', () => {
  const dir = fixture(CLEAN_WITH_WARN)
  try {
    const base = run([join(dir, 'm')])
    assert.equal(base.code, 0, 'warn alone must not fail by default (no surprise break for existing users)')
    assert.match(base.stdout, /--fail-on warn/, 'passing output must tell the reader warnings did not gate')

    assert.equal(run([join(dir, 'm'), '--fail-on', 'warn']).code, 1, '--fail-on warn → 1')
    assert.equal(run([join(dir, 'm'), '--fail-on=warn']).code, 1, '--fail-on=warn → 1')
    assert.equal(run([join(dir, 'm'), '--strict']).code, 1, '--strict alias → 1')
    assert.equal(run([join(dir, 'm')], { MIGRATION_GUARD_FAIL_ON: 'warn' }).code, 1, 'env var → 1')
    assert.equal(run([join(dir, 'm'), '--fail-on', 'fail']).code, 0, 'explicit --fail-on fail → 0')
    assert.equal(run([join(dir, 'm'), '--fail-on', 'banana']).code, 2, 'invalid level → usage error, not silent default')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// ONDA 0.1 — "could not read it" must never render as "it is clean".
test('an unterminated construct fails the build end-to-end', () => {
  const dir = fixture("/* never closed\ncreate table public.victim (id int);\nalter table public.other disable row level security;\n")
  try {
    const r = run([join(dir, 'm')])
    assert.equal(r.code, 1, 'unparsable file must fail the gate')
    assert.match(r.stdout, /unterminated|unparsable/i, 'and must say why')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
