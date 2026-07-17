import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { scanSql, finalizeTables, finalizeDrops, stripComments } from '../src/rules.mjs'
import { lint } from '../src/lint.mjs'
import { levelOf, fixFor, enrich, toMarkdown } from '../src/report.mjs'

const fx = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))

test('create table without RLS is a fail', () => {
  const { events } = scanSql('create table public.foo (id int);', 'm.sql')
  const findings = finalizeTables(events)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].rule, 'create_table_no_rls')
  assert.equal(findings[0].severity, 'fail')
})

test('create table WITH enable RLS clears the finding', () => {
  const sql = 'create table public.foo (id int); alter table public.foo enable row level security;'
  const { events } = scanSql(sql, 'm.sql')
  assert.equal(finalizeTables(events).length, 0)
})

test('enable RLS in a later file still clears the finding (cross-file)', () => {
  const a = scanSql('create table public.foo (id int);', 'a.sql')
  const b = scanSql('alter table public.foo enable row level security;', 'b.sql')
  assert.equal(finalizeTables([...a.events, ...b.events]).length, 0)
})

test('drop table + re-create WITHOUT rls is caught (no false negative)', () => {
  const sql =
    'create table public.p (id int); alter table public.p enable row level security;' +
    ' drop table public.p; create table public.p (id int);'
  const findings = finalizeTables(scanSql(sql, 'm.sql').events)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].rule, 'create_table_no_rls')
})

test('create table IF NOT EXISTS twice does not re-flag an enabled table', () => {
  const sql =
    'create table if not exists public.p (id int); alter table public.p enable row level security;' +
    ' create table if not exists public.p (id int);'
  assert.equal(finalizeTables(scanSql(sql, 'm.sql').events).length, 0)
})

test('tables in system schemas are ignored', () => {
  const { events } = scanSql('create table auth.sessions (id int);', 'm.sql')
  assert.equal(events.filter((e) => e.type === 'create').length, 0)
})

test('a PARTITION OF child is not flagged (inherits the parent RLS)', () => {
  const { events } = scanSql('create table public.p_2026 partition of public.p for values in (2026);', 'm.sql')
  assert.equal(finalizeTables(events).length, 0)
})

test('a PARTITION BY parent still needs RLS (not confused with a child)', () => {
  const sql = 'create table public.p (id int, created_at date) partition by range (created_at);'
  const findings = finalizeTables(scanSql(sql, 'm.sql').events)
  assert.equal(findings.filter((f) => f.rule === 'create_table_no_rls').length, 1)
})

test('a column literally named "partition" is not mistaken for a partition', () => {
  const { events } = scanSql('create table public.t (partition int);', 'm.sql')
  assert.equal(finalizeTables(events).length, 1) // still a normal table without RLS
})

test('disable RLS is a fail', () => {
  const { findings } = scanSql('alter table public.p disable row level security;', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'disable_rls' && f.severity === 'fail').length, 1)
})

test('USING (true) policy is a fail', () => {
  const { findings } = scanSql('create policy "x" on public.p for select using ( true );', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'permissive_true' && f.severity === 'fail').length, 1)
})

test('a scoped policy is not flagged', () => {
  const { findings } = scanSql('create policy "x" on public.p for select using (owner_id = auth.uid());', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'permissive_true').length, 0)
})

test('a USING (true) policy scoped only to service_role is NOT flagged', () => {
  const { findings } = scanSql('create policy "svc" on public.p for select to service_role using (true);', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'permissive_true').length, 0)
})

test('a USING (true) policy reaching authenticated IS flagged', () => {
  const { findings } = scanSql('create policy "x" on public.p for select to authenticated using (true);', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'permissive_true').length, 1)
})

test('a RESTRICTIVE using (true) policy is a no-op, not flagged', () => {
  const { findings } = scanSql('create policy "x" on public.p as restrictive for select using (true);', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'permissive_true').length, 0)
})

test('a net drop trigger (never re-created) is a warn', async () => {
  const a = scanSql('drop trigger if exists on_auth_user_created on auth.users;', 'm.sql')
  const { finalizeDrops } = await import('../src/rules.mjs')
  const out = finalizeDrops([], new Set(), a.droppedTriggers, a.recreatedTriggers)
  assert.equal(out.filter((f) => f.rule === 'drop_trigger' && f.severity === 'warn').length, 1)
})

test('a drop that is re-created in the same set is NOT flagged (no false positive)', async () => {
  const sql = 'drop trigger if exists t on public.p; create trigger t after insert on public.p execute function f();'
  const r = await lint({ files: [], allow: [] })
  // run through scan+finalize via a tiny inline set
  const a = scanSql(sql, 'm.sql')
  const { finalizeDrops } = await import('../src/rules.mjs')
  const net = finalizeDrops(a.droppedTriggers, a.recreatedTriggers, [], new Set())
  assert.equal(net.length, 0)
  assert.equal(r.files, 0)
})

test('baseline grants to anon/service_role are NOT flagged (Supabase default)', () => {
  const { findings } = scanSql('grant all on table public.t to anon; grant all on table public.t to service_role;', 'm.sql')
  assert.equal(findings.length, 0)
})

test('comments do not trip rules', () => {
  const { findings } = scanSql('-- alter table public.p disable row level security\nselect 1;', 'm.sql')
  assert.equal(findings.length, 0)
})

test('line numbers survive block comments', () => {
  const sql = '/* a\nb\nc */\nalter table public.p disable row level security;'
  const { findings } = scanSql(sql, 'm.sql')
  assert.equal(findings[0].line, 4)
})

test('a -- inside a string does NOT eat the next statement (no false negative)', () => {
  const sql = "insert into t values ('a--b'); create table public.d (id int);"
  const { events } = scanSql(sql, 'm.sql')
  assert.equal(finalizeTables(events).length, 1) // the create table is still seen
})

test('a keyword inside a string literal is not a finding (no false positive)', () => {
  const { findings } = scanSql("insert into log values ('alter table x disable row level security');", 'm.sql')
  assert.equal(findings.length, 0)
})

test('DDL inside a DO $$ block is still analyzed (create+enable balances)', () => {
  const sql = 'do $$ begin create table public.b (id int); alter table public.b enable row level security; end $$;'
  const { events } = scanSql(sql, 'm.sql')
  assert.equal(finalizeTables(events).length, 0)
})

test('lint(leaky) fails with the expected rules', async () => {
  const r = await lint({ files: [fx('leaky.sql')] })
  assert.equal(r.passed, false)
  const rules = new Set(r.findings.map((f) => f.rule))
  for (const expected of ['create_table_no_rls', 'permissive_true', 'disable_rls', 'drop_trigger']) {
    assert.ok(rules.has(expected), `expected rule ${expected}`)
  }
})

test('report: severity is graded and the fix is concrete', () => {
  assert.equal(levelOf('create_table_no_rls'), 'critical')
  assert.equal(levelOf('drop_trigger'), 'medium')
  const fix = fixFor({ rule: 'create_table_no_rls', object: 'public.invoices' })
  assert.match(fix, /alter table public\.invoices enable row level security/)
})

test('report: enrich adds level + fix to every finding', async () => {
  const r = enrich(await lint({ files: [fx('leaky.sql')] }))
  assert.ok(r.findings.every((f) => f.level && f.fix))
})

test('report: markdown export carries the fixes and severity', async () => {
  const md = toMarkdown(enrich(await lint({ files: [fx('leaky.sql')] })))
  assert.match(md, /# Migration Guard report/)
  assert.match(md, /\*\*FAILED\*\*/)
  assert.match(md, /🔴 CRITICAL/)
  assert.match(md, /\*\*Fix:\*\*/)
  assert.match(md, /```sql/)
})

test('lint(clean) passes', async () => {
  const r = await lint({ files: [fx('clean.sql')] })
  assert.equal(r.passed, true)
  assert.equal(r.problems, 0)
})

test('allow-list silences a finding by table name', async () => {
  const r = await lint({ files: [fx('leaky.sql')], allow: ['invoices', 'profiles', 'rule:drop_trigger'] })
  // invoices (create+permissive) and profiles (disable) and the trigger all silenced → passes
  assert.equal(r.passed, true)
  assert.ok(r.allowed.length >= 4)
})
