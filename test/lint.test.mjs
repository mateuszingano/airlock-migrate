import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { scanSql, finalizeTables, finalizeDrops, stripComments } from '../src/rules.mjs'
import { lint } from '../src/lint.mjs'
import { levelOf, fixFor, enrich, toMarkdown } from '../src/report.mjs'
import { buildPayload, reportRun } from '../src/report-ci.mjs'

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

// ---- P2 fix #1: dollar-quoted DATA string is not analyzed as code ----
test('#1 a dollar-quoted STRING used as data does NOT trip a rule (was a false positive)', () => {
  const sql = 'select $doc$ alter table public.p disable row level security $doc$ as note;'
  const { findings } = scanSql(sql, 'm.sql')
  assert.equal(findings.length, 0)
})

test('#1 a create table inside a dollar-quoted data string is NOT counted', () => {
  const sql = "insert into docs (body) values ($x$ create table public.leak (id int) $x$);"
  const { events } = scanSql(sql, 'm.sql')
  assert.equal(finalizeTables(events).length, 0)
})

test('#1 dynamic execute of a DISABLE inside a DO block IS still caught (real DDL)', () => {
  const sql = "do $$ begin execute 'alter table public.p disable row level security'; end $$;"
  const { findings } = scanSql(sql, 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'disable_rls').length, 1)
})

// ---- P2 fix #3: UNLOGGED / FOREIGN tables are scanned; TEMP is not ----
test('#3 create UNLOGGED table without RLS is a fail', () => {
  const { events } = scanSql('create unlogged table public.u (id int);', 'm.sql')
  assert.equal(finalizeTables(events).filter((f) => f.rule === 'create_table_no_rls').length, 1)
})

test('#3 create FOREIGN table without RLS is a fail', () => {
  const { events } = scanSql('create foreign table public.f (id int) server s;', 'm.sql')
  assert.equal(finalizeTables(events).filter((f) => f.rule === 'create_table_no_rls').length, 1)
})

test('#3 a TEMP / TEMPORARY table is session-local and NOT flagged', () => {
  assert.equal(finalizeTables(scanSql('create temp table t (id int);', 'm.sql').events).length, 0)
  assert.equal(finalizeTables(scanSql('create temporary table t2 (id int);', 'm.sql').events).length, 0)
})

// P3 re-audit: SELECT ... INTO creates a table with RLS OFF
test('#selectinto SELECT ... INTO <table> without RLS is a fail', () => {
  const { events } = scanSql('select * into public.report from sales;', 'm.sql')
  assert.equal(finalizeTables(events).filter((f) => f.rule === 'create_table_no_rls').length, 1)
})

test('#selectinto SELECT INTO followed by ENABLE RLS is clean', () => {
  const sql = 'select * into public.report from sales; alter table public.report enable row level security;'
  assert.equal(finalizeTables(scanSql(sql, 'm.sql').events).length, 0)
})

test('#selectinto PL/pgSQL SELECT INTO <var> inside a body is NOT a table (no false positive)', () => {
  const fn = 'create function f() returns void as $$ begin select id into rec from t; end $$ language plpgsql;'
  assert.equal(finalizeTables(scanSql(fn, 'm.sql').events).length, 0)
  const doblk = 'do $$ begin select id into v from t; end $$;'
  assert.equal(finalizeTables(scanSql(doblk, 'm.sql').events).length, 0)
})

test('#selectinto a TEMP select-into and a plain INSERT INTO are NOT flagged', () => {
  assert.equal(finalizeTables(scanSql('select * into temp scratch from t;', 'm.sql').events).length, 0)
  assert.equal(finalizeTables(scanSql('insert into logs select * from events;', 'm.sql').events).length, 0)
})

test('#selectinto SELECT ... INTO WITHOUT a FROM is still caught', () => {
  const { events } = scanSql('select gen_random_uuid() into public.ids;', 'm.sql')
  assert.equal(finalizeTables(events).filter((f) => f.rule === 'create_table_no_rls').length, 1)
  // a CTE that ends in SELECT INTO too
  const cte = 'with s as (select 1 x) select x into public.derived from s;'
  assert.equal(finalizeTables(scanSql(cte, 'm.sql').events).filter((f) => f.rule === 'create_table_no_rls').length, 1)
})

// re-audit: nested parens must not slip past the flagship USING(true) check
test('#nestedtrue USING((true)) / WITH CHECK(( true )) is flagged (nested parens)', () => {
  assert.equal(scanSql('create policy p on public.t for select using ((true));', 'm.sql')
    .findings.filter((f) => f.rule === 'permissive_true').length, 1)
  assert.equal(scanSql('create policy p on public.t for insert with check (( true ));', 'm.sql')
    .findings.filter((f) => f.rule === 'permissive_true').length, 1)
  // a real predicate in parens is still NOT flagged
  assert.equal(scanSql('create policy p on public.t for select using ((owner_id = auth.uid()));', 'm.sql')
    .findings.filter((f) => f.rule === 'permissive_true').length, 0)
})

// re-audit follow-up: SPACED / tabbed nesting must not escape either
test('#spacedtrue USING with spaces/tabs between the parens is still flagged', () => {
  const variants = [
    'create policy p on public.t for select using ( (true) );',
    'create policy p on public.t for select using (  ( true )  );',
    'create policy p on public.t for select using (\t(\ttrue\t)\t);',
    'create policy p on public.t for select using ( ( ( true ) ) );',
    'create policy p on public.t for insert with check ( ( true ) );',
    'create policy p on public.t for select using (\n  ( true )\n);',
  ]
  for (const sql of variants) {
    assert.equal(
      scanSql(sql, 'm.sql').findings.filter((f) => f.rule === 'permissive_true').length,
      1,
      `expected flagged: ${JSON.stringify(sql)}`
    )
  }
  // a spaced real predicate stays clean
  assert.equal(scanSql('create policy p on public.t for select using ( ( status = 1 ) );', 'm.sql')
    .findings.filter((f) => f.rule === 'permissive_true').length, 0)
})

// ---- P2 fix #4: CREATE POLICY without a trailing ; ----
test('#4 a permissive policy as the last statement WITHOUT a ; is still caught', () => {
  const { findings } = scanSql('create policy "open" on public.p for select using (true)', 'm.sql')
  assert.equal(findings.filter((f) => f.rule === 'permissive_true').length, 1)
})

test('#4 a missing ; does not bleed into and mis-flag the next policy', () => {
  // "a" is scoped (safe) but has no ;, "b" is the permissive one — only b must flag.
  const sql =
    'create policy "a" on public.p for select using (owner_id = auth.uid()) ' +
    'create policy "b" on public.p for select using (true);'
  const { findings } = scanSql(sql, 'm.sql')
  const flagged = findings.filter((f) => f.rule === 'permissive_true')
  assert.equal(flagged.length, 1)
  assert.match(flagged[0].object, /^b on/)
})

// ---- P2 fix #2: line numbers correct + large file scans fast ----
test('#2 line numbers are correct across many lines (binary-search lookup)', () => {
  const sql = 'select 1;\n'.repeat(500) + 'alter table public.p disable row level security;'
  const { findings } = scanSql(sql, 'm.sql')
  assert.equal(findings[0].line, 501)
})

test('#2 a large single file scans fast (no quadratic lineOf)', () => {
  const sql = 'create table public.t (id int); alter table public.t enable row level security;\n'.repeat(8000)
  const start = Date.now()
  const { events } = scanSql(sql, 'm.sql')
  const ms = Date.now() - start
  assert.equal(finalizeTables(events).length, 0) // every table is enabled
  assert.ok(ms < 2000, `scan took ${ms}ms — expected < 2000ms (perf guard)`)
})

test('lint(leaky) fails with the expected rules', async () => {
  const r = await lint({ files: [fx('leaky.sql')] })
  assert.equal(r.passed, false)
  const rules = new Set(r.findings.map((f) => f.rule))
  for (const expected of ['create_table_no_rls', 'permissive_true', 'disable_rls', 'drop_trigger']) {
    assert.ok(rules.has(expected), `expected rule ${expected}`)
  }
})

test('report-ci: builds a payload with tool, verdict and findings', () => {
  const p = buildPayload({ passed: false, problems: 1, warnings: 0, findings: [{ rule: 'disable_rls', severity: 'fail', file: 'm.sql', line: 3, object: 'public.p', detail: 'x' }] }, { tool: 'airlock-migrate', version: '0.2.0' })
  assert.equal(p.tool, 'airlock-migrate')
  assert.equal(p.passed, false)
  assert.equal(p.findings.length, 1)
  assert.equal(p.findings[0].rule, 'disable_rls')
})

test('report-ci: no token → nothing is sent (stays free)', async () => {
  let called = false
  const res = await reportRun({ passed: true, findings: [] }, { tool: 't', version: '1', fetchImpl: async () => ((called = true), { ok: true }) })
  assert.equal(res.sent, false)
  assert.equal(called, false)
})

test('report-ci: with a token → POSTs to /api/ci/ingest with Bearer auth', async () => {
  let seen
  const fetchImpl = async (url, opts) => ((seen = { url, opts }), { ok: true, status: 200 })
  const res = await reportRun({ passed: false, problems: 1, findings: [] }, { tool: 'airlock-migrate', version: '0.2.0', token: 'tok_123', fetchImpl })
  assert.equal(res.sent, true)
  assert.match(seen.url, /\/api\/ci\/ingest$/)
  assert.equal(seen.opts.headers.Authorization, 'Bearer tok_123')
})

test('report-ci: a network error never throws (build is never broken)', async () => {
  const res = await reportRun({ findings: [] }, { tool: 't', version: '1', token: 'x', fetchImpl: async () => { throw new Error('boom') } })
  assert.equal(res.sent, false)
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

// NEW COVERAGE (was declared "not covered yet"): a view/matview in `public` runs
// with the owner's rights and bypasses the RLS of its underlying tables.
test('#view a public view without security_invoker is flagged (RLS bypass)', () => {
  const rules = sql => scanSql(sql, 'm.sql').findings.map(f => f.rule)
  assert.ok(rules('create view public.all_notes as select * from notes;').includes('view_bypasses_rls'))
  assert.ok(rules('create materialized view public.mv as select * from tenants;').includes('view_bypasses_rls'))
  // opts into security_invoker (any PG boolean spelling) → safe; non-public schema → not client-reachable
  assert.ok(!rules('create view public.v with (security_invoker = on) as select * from notes;').includes('view_bypasses_rls'))
  assert.ok(!rules('create view public.v with (security_invoker = yes) as select * from notes;').includes('view_bypasses_rls'))
  assert.ok(!rules('create view internal.v as select * from notes;').includes('view_bypasses_rls'))
})

// NEW COVERAGE: a SECURITY DEFINER function with no pinned search_path can be
// hijacked into running as its owner. Supabase's guidance is SET search_path = ''.
test('#definer a SECURITY DEFINER function without a pinned search_path is flagged', () => {
  const rules = sql => scanSql(sql, 'm.sql').findings.map(f => f.rule)
  assert.ok(rules('create function public.f() returns int language sql security definer as $$ select 1 $$;').includes('definer_no_search_path'))
  assert.ok(rules('create or replace function g() returns trigger security definer language plpgsql as $$ begin return new; end $$;').includes('definer_no_search_path'))
  // pinned search_path (either order) → safe; a plain (invoker) function → not flagged
  assert.ok(!rules("create function f() returns int language sql security definer set search_path = '' as $$ select 1 $$;").includes('definer_no_search_path'))
  assert.ok(!rules("create function f() returns trigger language plpgsql set search_path='' security definer as $$ begin return new; end $$;").includes('definer_no_search_path'))
  assert.ok(!rules('create function f() returns int language sql as $$ select 1 $$;').includes('definer_no_search_path'))
})

// NEW COVERAGE (was declared "not covered yet"): a policy predicate that reduces to
// a CONSTANT tautology — 1=1, 2>1, reflexive col=col, 1 in (1), length()>=0 — is
// as permissive as USING(true). A column-vs-literal or real column stays clean.
test('#tautology a constant/reflexive always-true predicate is flagged; real predicates are not', () => {
  const hit = u => scanSql(`create policy p on public.t for select to anon using (${u});`, 'm.sql').findings.some(f => f.rule === 'permissive_true')
  for (const u of ['1=1', '2 > 1', "'a' = 'a'", 'owner_id = owner_id', '((1=1))', 'tenant = owner OR 2=2', '1 in (1)', 'length(name) >= 0'])
    assert.ok(hit(u), `expected ${u} flagged as always-true`)
  for (const u of ['is_active = true', 'owner_id = auth.uid()', "status = 'active'", '1=2', 'tenant_id = owner_id', 'a = b', 'role in (\'a\',\'b\')', 'email in (select id from admins)'])
    assert.ok(!hit(u), `expected ${u} NOT flagged`)
  // restrictive / server-role stay clean even when always-true
  assert.ok(!scanSql('create policy p on public.t as restrictive for select to anon using (1=1);', 'm.sql').findings.some(f => f.rule === 'permissive_true'))
  assert.ok(!scanSql('create policy p on public.t for select to service_role using (1=1);', 'm.sql').findings.some(f => f.rule === 'permissive_true'))
})

// ONDA 0 — the "green because unreadable" invariant. An unterminated string /
// block comment / dollar-quote blanks everything after it, so real DDL further
// down vanished and the gate went GREEN: the more broken the file, the greener
// the CI. A gate must never approve text it could not read.
test('#unparsable an unterminated construct fails instead of silently swallowing the rest', () => {
  const DDL = 'create table public.victim (id int);\nalter table public.other disable row level security;'
  const rules = (sql) => scanSql(sql, 'm.sql').findings
  // control: the DDL is caught when nothing hides it
  assert.ok(rules(DDL).some(f => f.rule === 'disable_rls'), 'control: disable_rls must be caught')
  // each opener used to swallow the DDL below it — now each is a hard fail
  for (const prefix of ['select $doc$ this never closes\n', "insert into t values ('oops\n", '/* never closed\n', 'select $1$ x\n']) {
    const found = rules(prefix + DDL)
    assert.ok(found.some(f => f.rule === 'unparsable' && f.severity === 'fail'), `expected unparsable fail for: ${prefix.trim()}`)
  }
  // and a well-formed file must NOT be flagged (no false positive on the happy path)
  for (const ok of [DDL, "select $doc$ closed $doc$;\n" + DDL, "insert into t values ('fine');\n" + DDL, '/* closed */\n' + DDL])
    assert.ok(!rules(ok).some(f => f.rule === 'unparsable'), 'well-formed SQL must not be flagged unparsable')
})

// The existing perf test only exercised `create table`, which was always linear.
// The three shapes that actually hung CI were never measured: a 628KB migration
// took 18.4s, and ~1MB of DO blocks took over two minutes. Causes were a slice
// to end-of-file per match, two regexes scanning to EOF for an anchor that lives
// in the same statement, a linear range lookup per match, and a lookback regex
// run against the entire accumulated output.
test('#perf the shapes that used to hang CI stay linear', () => {
  const shapes = {
    'view without AS': (n) => Array.from({ length: n }, (_, i) => `create view v${i} `).join('\n'),
    'view complete': (n) => Array.from({ length: n }, (_, i) => `create view v${i} as select * from t${i};`).join('\n'),
    'DO blocks + select into': (n) => Array.from({ length: n }, (_, i) => `do $$ begin end $$;\nselect x into t${i} from y;`).join('\n'),
    'trigger without ON': (n) => Array.from({ length: n }, (_, i) => `create trigger tg${i} `).join('\n'),
    'table + enable rls': (n) => Array.from({ length: n }, (_, i) => `create table public.t${i} (id int);\nalter table public.t${i} enable row level security;`).join('\n'),
  }
  for (const [name, gen] of Object.entries(shapes)) {
    const t0 = Date.now()
    scanSql(gen(20000), 'm.sql')
    const ms = Date.now() - t0
    // Generous ceiling: the point is to catch a return to quadratic (which put
    // these in the tens of seconds to minutes), not to police small regressions.
    assert.ok(ms < 5000, `${name} took ${ms}ms for 20k statements — quadratic behaviour is back`)
  }
})

// `\b(anon)\b` does NOT match `web_anon` — `_` is a word character — so every
// policy written with the role name from the official PostgREST tutorial was
// judged unreachable by a client and passed clean, including FOR ALL USING(true).
test('#roles client-reachable roles are matched as whole segments', () => {
  const flagged = (to) => scanSql(`create policy p on public.t for all to ${to} using (true) with check (true);`, 'm.sql')
    .findings.some((f) => f.rule === 'permissive_true')
  for (const r of ['anon', 'authenticated', 'public', 'web_anon', 'web_user', '"web_anon"', 'WEB_ANON', 'anon, service_role'])
    assert.ok(flagged(r), `TO ${r} must be treated as client-reachable`)
  // and a role that merely CONTAINS one of those words must not be
  for (const r of ['service_role', 'my_custom_role', 'anon_users', 'postgres', 'authenticator'])
    assert.ok(!flagged(r), `TO ${r} must NOT be treated as client-reachable`)
})

// Postgres nests block comments; this parser closed at the first `*/`, so SQL a
// developer had commented out — with a comment already inside it — came back as
// live DDL and produced a CRITICAL for a table that does not exist.
test('#comments nested block comments are one comment, per Postgres rules', () => {
  const tables = (sql) => {
    const r = scanSql(sql, 'm.sql')
    return finalizeTables(r.events).map((f) => f.object)
  }
  assert.deepEqual(tables('/* disabled: /* why */ create table public.ghost (id int); */'), [], 'fully commented out → nothing')
  assert.deepEqual(tables('/* a /* b */ c */ create table public.real (id int);'), ['public.real'], 'DDL after the true close is live')
  assert.deepEqual(tables('/* plain */ create table public.real2 (id int);'), ['public.real2'], 'ordinary comments still work')
})

// A create ANYWHERE used to cancel a drop, including one that came first — where
// the end state is "object removed". That is the exact `on_auth_user_created`
// shape the README uses as its headline scar.
test('#order a drop is only cancelled by a create that comes AFTER it', () => {
  const TRG = 'on_auth_user_created'
  const create = `create trigger ${TRG} after insert on auth.users for each row execute function handle_new_user();`
  const drop = `drop trigger ${TRG} on auth.users;`
  const run = (sql) => {
    const r = scanSql(sql, 'm.sql')
    return finalizeDrops([], new Map(), r.droppedTriggers.map((d) => ({ ...d, pos: d.index })), r.recreatedTriggers)
  }
  assert.equal(run(`${create}\n${drop}`).length, 1, 'create then drop → ends WITHOUT the trigger → must warn')
  assert.equal(run(`${drop}\n${create}`).length, 0, 'drop then create → ends WITH the trigger → must stay quiet')
})

// A table outside `public` is not API-reachable unless the schema is exposed via
// db-schemas — and "hide internal tables in a private schema" is Supabase's own
// recommendation. Reporting it CRITICAL broke the build of people who followed
// the official advice.
test('#schema a table outside public is a warn, not a blocking CRITICAL', () => {
  const sev = (sql) => {
    const r = scanSql(sql, 'm.sql')
    return finalizeTables(r.events).map((f) => f.severity)
  }
  assert.deepEqual(sev('create table public.t (id int);'), ['fail'])
  assert.deepEqual(sev('create table t (id int);'), ['fail'], 'unqualified means public')
  assert.deepEqual(sev('create schema private;\ncreate table private.internal_jobs (id int);'), ['warn'])
})

// `do LANGUAGE plpgsql $$` decided "executable?" from the token next to the
// opener, saw `plpgsql`, and blanked the whole block — so DDL inside it, up to
// and including `disable row level security`, vanished and the gate went green.
// One optional, perfectly valid keyword turned the scanner off.
test('#doblock an executable body is analyzed however the statement is written', () => {
  const BODY = "begin\n execute 'alter table public.secrets disable row level security';\n create table public.leaky (id int);\nend"
  const rules = (sql) => {
    const r = scanSql(sql, 'm.sql')
    return [...r.findings, ...finalizeTables(r.events)].map((f) => f.rule)
  }
  for (const open of ['do $$', 'do language plpgsql $$', 'DO LANGUAGE PLPGSQL $$']) {
    const found = rules(`${open}\n${BODY}\n$$;`)
    assert.ok(found.includes('disable_rls'), `${open} — the body must be analyzed`)
  }
  // a function body, LANGUAGE declared before or after AS
  assert.ok(rules(`create function f() returns void language plpgsql as $$\n${BODY}\n$$;`).includes('disable_rls'))
  assert.ok(rules('create function g() returns void as $$\n create table public.leaky3 (id int);\n$$ language sql;').includes('create_table_no_rls'))
  // …and a dollar-quoted STRING is still treated as data (no false positive)
  assert.deepEqual(rules("select $doc$ create table public.ghost (id int); disable row level security $doc$;"), [])
  assert.deepEqual(rules('insert into t values ($$ create table public.ghost2 (id int); $$);'), [])
})

// SYSTEM_SCHEMAS is a fixed list, so a project's own `auth`/`cron` schema — or a
// real table added to Supabase's — disappeared from the analysis with no trace.
// Skipping stays right; skipping SILENTLY does not.
test('#skipped a table in a system schema is reported as skipped, not omitted', () => {
  const findings = (sql) => scanSql(sql, 'm.sql').findings
  for (const schema of ['auth', 'cron', 'vault']) {
    const f = findings(`create table ${schema}.mine (id int);`)
    assert.ok(f.some((x) => x.rule === 'skipped_system_schema'), `${schema} must be reported as skipped`)
    assert.ok(f.every((x) => x.severity !== 'fail'), 'and it is a warn, not a build break')
  }
  // a schema that merely LOOKS like a system one is analyzed normally
  assert.deepEqual(findings('create table auth_v2.t (id int);').filter((x) => x.rule === 'skipped_system_schema'), [])
})

// ── ALTER POLICY (the Critical that survived every earlier audit) ──
//
// Only `create policy` had a regex, so widening an EXISTING policy — which is
// what an adjustment migration actually does — was invisible. A complete tenant
// leak exited 0 under "No dangerous migrations", on the rule the README leads
// with. These lock the behavior in both directions.
const perm = (sql) => scanSql(sql, 'm.sql').findings.filter((f) => f.rule === 'permissive_true')

test('#alter ALTER POLICY … USING (true) is a fail, not invisible', () => {
  const f = perm('alter policy "user reads own rows" on public.payments using (true);')
  assert.equal(f.length, 1, 'the leak must be caught')
  assert.equal(f[0].severity, 'fail', 'and it must break the build')
})

test('#alter an ALTER POLICY tautology is caught like a CREATE one', () => {
  assert.equal(perm('alter policy p on public.t using (1=1);').length, 1)
  assert.equal(perm('alter policy p on public.t using (owner_id = owner_id);').length, 1)
  assert.equal(perm('alter policy p on public.t with check (true);').length, 1)
})

test('#alter with no TO clause it inherits the roles of the CREATE in the same run', () => {
  assert.equal(
    perm(`create policy p on public.orders for select to anon using (auth.uid() = user_id);
          alter policy p on public.orders using (true);`).length,
    1,
    'created for anon, then widened → fail'
  )
  assert.equal(
    perm(`create policy p on public.jobs for select to service_role using (auth.uid() = user_id);
          alter policy p on public.jobs using (true);`).length,
    0,
    'a service_role-only policy is not client-reachable, widened or not'
  )
})

test('#alter its own TO clause wins over the inherited one', () => {
  assert.equal(perm('alter policy p on public.t to service_role using (true);').length, 0)
  assert.equal(perm('alter policy p on public.t to anon using (true);').length, 1)
})

test('#alter legitimate ALTER POLICY statements stay silent (no false alarms)', () => {
  assert.equal(perm('alter policy p on public.t using (auth.uid() = user_id);').length, 0)
  assert.equal(perm('alter policy p on public.t using (owner = auth.uid()) with check (owner = auth.uid());').length, 0)
  assert.equal(perm('alter policy p on public.t rename to p_new;').length, 0)
})

// ── one producer of "this body is executable" ──
//
// There used to be two: stripComments decided from the statement head (so it
// accepted `do$$`), and a separate executableBodyRanges regex required
// `do\s+$$`. With no space the body was kept as code but not marked executable,
// so a PL/pgSQL `SELECT … INTO v` inside it read as a table creation — a
// blocking CRITICAL decided by one character. The second producer is gone; this
// pins the property that made the divergence possible.
test('#exec whitespace before the dollar tag does not change the verdict', () => {
  for (const kw of ['do', 'as']) {
    const spaced = {}, tight = {}
    stripComments(`${kw} $$ body $$`, spaced)
    stripComments(`${kw}$$ body $$`, tight)
    assert.equal(spaced.executableRanges.length, 1, `${kw} $$ is executable`)
    assert.equal(tight.executableRanges.length, 1, `${kw}$$ is executable too`)
  }
})

test('#exec a data dollar-string is still NOT an executable range', () => {
  const st = {}
  stripComments("select $doc$ create table public.x (id int); $doc$;", st)
  assert.equal(st.executableRanges.length, 0, 'documentation text is data, not DDL')
})

test('#exec an unterminated executable body stays executable to EOF', () => {
  const st = {}
  stripComments('do $$\nbegin\n  select 1 into v from t;', st)
  assert.equal(st.executableRanges.length, 1)
  assert.ok(st.unterminated, 'and it is still reported as unterminated')
})

// ── quoted identifiers ──
//
// IDENT used to be `"?[\w]+"?`, so a quoted name stopped at the first
// non-word character: `create table "my table"` was recorded as `public.my`,
// the matching ALTER never lined up with it, and the run failed with a
// CRITICAL on a table whose RLS was in fact enabled. Two names sharing a first
// word also collapsed onto one key, so a real miss could be silenced.
const tableFindings = (sql) => {
  const { findings, events } = scanSql(sql, 'm.sql')
  return [...findings, ...finalizeTables(events || [])]
}

test('#quoted a quoted table name is not truncated at the space', () => {
  const f = tableFindings(`create table "my table" (id int);
                           alter table "my table" enable row level security;`)
  assert.deepEqual(f.filter((x) => x.rule === 'create_table_no_rls'), [], 'RLS IS enabled — no false alarm')
})

test('#quoted two quoted names sharing a first word do not collide', () => {
  const f = tableFindings(`create table "my table" (id int);
                           alter table "my table" enable row level security;
                           create table "my other table" (id int);`)
  const missed = f.filter((x) => x.rule === 'create_table_no_rls')
  assert.equal(missed.length, 1, 'the second table is genuinely missing RLS')
  assert.match(missed[0].object, /my other table/)
})

test('#quoted the suggested fix is runnable SQL, not a syntax error', () => {
  assert.match(
    fixFor({ rule: 'create_table_no_rls', object: 'public.my other table' }),
    /alter table public\."my other table" enable row level security;/,
  )
})

test('#quoted a dot inside a quoted name is part of the name, not a qualifier', () => {
  const f = tableFindings('create table "my.table" (id int);')
  const missed = f.filter((x) => x.rule === 'create_table_no_rls')
  assert.equal(missed.length, 1)
  assert.equal(missed[0].object, 'public.my.table', 'schema stays public; the dot is in the name')
})

// ── the printed label must agree with the exit code ──
//
// LEVELS was a second, independent map with a `|| 'medium'` default, so a rule
// missing from it printed [MEDIUM] regardless of what it did. `unparsable` is a
// `fail` — it breaks the build — and printed MEDIUM next to a red exit 1. The
// label now derives from the severity the engine assigned, so omission can only
// make a label coarse, never wrong.
test('#label no fail is ever printed below HIGH, and no warn above MEDIUM', () => {
  const rules = [
    'create_table_no_rls', 'disable_rls', 'permissive_true', 'drop_policy',
    'drop_trigger', 'unparsable', 'view_bypasses_rls', 'definer_no_search_path',
    'skipped_system_schema', 'a_rule_added_next_year',
  ]
  for (const rule of rules) {
    assert.ok(
      ['critical', 'high'].includes(levelOf(rule, 'fail')),
      `${rule}: a build-breaking finding must not print below HIGH`,
    )
    assert.ok(
      ['medium', 'low'].includes(levelOf(rule, 'warn')),
      `${rule}: a non-blocking finding must not print above MEDIUM`,
    )
  }
})

test('#label unparsable — the rule that was mislabelled — prints as a build-breaker', () => {
  assert.equal(levelOf('unparsable', 'fail'), 'high')
  assert.equal(levelOf('create_table_no_rls', 'fail'), 'critical', 'and grading within fail is preserved')
})

// A fixed 400-chunk lookback window used to decide whether a dollar body was
// executable. A function header longer than the window — a wide argument list,
// clauses between AS and the body — pushed the opening keyword out of view, the
// body was blanked as if it were data, and every rule inside it went quiet with
// no signal. Anchoring to the statement start removes the cliff entirely.
test('#window a long function header does not silence its body', () => {
  for (const gap of [10, 350, 600, 5000]) {
    const sql = `create function f(a int)\nreturns void\n${'  -- ' + 'x'.repeat(gap) + '\n'}as $$\n  create table public.leak (id int);\n$$ language plpgsql;`
    const st = {}
    stripComments(sql, st)
    assert.equal(st.executableRanges.length, 1, `a ${gap}-char header must not hide the body`)
  }
})

test('#window scanning stays linear on DO-heavy input', () => {
  const sql = Array.from({ length: 20_000 }, (_, i) => `do $$ begin perform ${i}; end $$;`).join('\n')
  const t0 = Date.now()
  stripComments(sql, {})
  const ms = Date.now() - t0
  // Measured ~45ms locally. A generous ceiling still catches a return to the
  // quadratic behaviour this replaced, without flaking on a slow CI runner.
  assert.ok(ms < 4000, `stripComments took ${ms}ms on 20k DO blocks — expected linear time`)
})

// ── SECURITY DEFINER / SET search_path on either side of the body ──
//
// Postgres accepts both clauses before OR after the body, and Supabase's own
// generator emits them AFTER. Reading only the pre-AS header was wrong in both
// directions: a trailing SECURITY DEFINER was invisible (false negative), and a
// trailing SET search_path did not count as pinned, so a correctly-hardened
// function was warned about (false alarm).
const definer = (sql) => scanSql(sql, 'm.sql').findings.filter((f) => f.rule === 'definer_no_search_path').length

test('#definer a SECURITY DEFINER declared after the body is caught', () => {
  assert.equal(definer('create function g() returns void as $$ select 1; $$ language sql security definer;'), 1)
  assert.equal(definer('create function g() returns void security definer as $$ select 1; $$ language sql;'), 1)
})

test('#definer a SET search_path declared after the body counts as pinned', () => {
  assert.equal(
    definer("create function g() returns void security definer as $$ select 1; $$ language sql set search_path = '';"),
    0,
    'a hardened function must not be warned about',
  )
  assert.equal(
    definer("create function g() returns void security definer set search_path = '' as $$ select 1; $$ language sql;"),
    0,
  )
})

test('#definer the clauses are read from the statement, never from the body', () => {
  assert.equal(
    definer('create function g() returns void as $$ select 1; -- security definer\n $$ language sql;'),
    0,
    'the words inside a body are code/comment, not clauses',
  )
  assert.equal(definer('create function g() returns void as $$ select 1; $$ language sql;'), 0)
})

// ── the allow-list must not become a kill switch ──
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

async function fixtureDir() {
  const dir = await mkdtemp(join(tmpdir(), 'mg-allow-'))
  await writeFile(join(dir, 'a.sql'), 'create table public.secrets (id int);\n')
  await writeFile(join(dir, 'b.sql'), "create policy p on public.t for select to anon using ('unterminated;\n")
  return dir
}

test('#allow a bare * is refused instead of silencing the whole gate', async () => {
  const dir = await fixtureDir()
  try {
    await assert.rejects(() => lint({ dir, allow: ['*'] }), /disable the gate entirely/)
    const clean = await lint({ dir })
    assert.equal(clean.passed, false, 'and without it the findings are still there')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('#allow unparsable is only waivable by its rule, never by a path segment', async () => {
  const dir = await fixtureDir()
  try {
    // Every migration file name ends in "sql", so an object-segment match on it
    // silenced the finding that says "this file was never checked".
    const bySegment = await lint({ dir, allow: ['sql'] })
    assert.ok(
      bySegment.findings.some((f) => f.rule === 'unparsable'),
      '--allow sql must not waive "I could not read this file"',
    )
    const byRule = await lint({ dir, allow: ['rule:unparsable'] })
    assert.ok(
      !byRule.findings.some((f) => f.rule === 'unparsable'),
      'the explicit, deliberate form still works',
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// ---------------------------------------------------------------------------
// Regressions from the 20/07 audit. Each of the five below shipped GREEN, exit
// 0, on code whose whole job was to catch it.
// ---------------------------------------------------------------------------

test('#altertable IF EXISTS does not hide a DISABLE ROW LEVEL SECURITY', () => {
  const { findings } = scanSql('alter table if exists public.users disable row level security;', 'm.sql')
  assert.equal(findings.length, 1)
  assert.equal(findings[0].rule, 'disable_rls')
  assert.equal(findings[0].object, 'public.users')
})

test('#altertable the descendant "*" does not hide a DISABLE either', () => {
  const { findings } = scanSql('alter table only public.users * disable row level security;', 'm.sql')
  assert.equal(findings.length, 1)
  assert.equal(findings[0].rule, 'disable_rls')
})

test('#altertable IF EXISTS / "*" are also read on the ENABLE side', () => {
  // Otherwise the fix above would turn into a false positive: the CREATE stays
  // unmatched and reports a table whose RLS is in fact on.
  const sql =
    'create table public.foo (id int); alter table if exists only public.foo * enable row level security;'
  assert.equal(finalizeTables(scanSql(sql, 'm.sql').events).length, 0)
})

test('#tautology NOT / AND / IS NULL constants are always-true predicates', () => {
  for (const pred of ['not false', 'true and true', 'null is null', 'not (1 = 2)', "'a' is not null"]) {
    const sql = `create policy p on public.t for select to anon using (${pred});`
    const { findings } = scanSql(sql, 'm.sql')
    assert.ok(
      findings.some((f) => f.rule === 'permissive_true'),
      `USING (${pred}) grants every row and must be caught`,
    )
  }
})

test('#tautology a real predicate is still not flagged (no false positives)', () => {
  for (const pred of [
    'auth.uid() = user_id',
    'deleted_at is null',
    'not is_private',
    'tenant_id = current_tenant() and auth.uid() = user_id',
    "role = 'admin' or auth.uid() = user_id",
    'length(name) >= 5',
  ]) {
    const sql = `create policy p on public.t for select to anon using (${pred});`
    const { findings } = scanSql(sql, 'm.sql')
    assert.ok(
      !findings.some((f) => f.rule === 'permissive_true'),
      `USING (${pred}) depends on the row — flagging it would be a false alarm`,
    )
  }
})

test('#tautology an OR inside a string literal is one operand, not a split', () => {
  const sql = "create policy p on public.t for select to anon using (name = 'a or b');"
  const { findings } = scanSql(sql, 'm.sql')
  assert.ok(!findings.some((f) => f.rule === 'permissive_true'))
})

test('#dynamic DDL assembled at runtime that touches RLS breaks the build', () => {
  for (const stmt of [
    "execute format('alter table %I disable row level security', t);",
    "execute 'alter table ' || t || ' disable row level security';",
    "execute format('create policy %I on %I for select using (true)', p, t);",
  ]) {
    const { findings } = scanSql(`do $$ begin\n  ${stmt}\nend $$;`, 'm.sql')
    const f = findings.find((x) => x.rule === 'dynamic_ddl_unanalyzed')
    assert.ok(f, `dynamic DDL must not be reported as clean: ${stmt}`)
    assert.equal(f.severity, 'fail')
  }
})

test('#dynamic other dynamic DDL warns rather than breaking the build', () => {
  const sql = "do $$ begin\n  execute format('create index on %I (id)', t);\nend $$;"
  const { findings } = scanSql(sql, 'm.sql')
  const f = findings.find((x) => x.rule === 'dynamic_ddl_unanalyzed')
  assert.ok(f)
  assert.equal(f.severity, 'warn')
})

test('#dynamic a plain literal EXECUTE is analyzed, not merely reported as opaque', () => {
  const { findings } = scanSql(
    "do $$ begin\n  execute 'alter table public.a disable row level security';\nend $$;",
    'm.sql',
  )
  assert.ok(findings.some((f) => f.rule === 'disable_rls'), 'the literal is still read')
  assert.ok(
    !findings.some((f) => f.rule === 'dynamic_ddl_unanalyzed'),
    'and it is NOT also reported as unreadable',
  )
})

test('#dynamic a trigger EXECUTE FUNCTION clause is not dynamic SQL', () => {
  const sql =
    "do $$ begin\n  create trigger tg after insert on public.t for each row execute function f();\nend $$;"
  const { findings } = scanSql(sql, 'm.sql')
  assert.ok(!findings.some((f) => f.rule === 'dynamic_ddl_unanalyzed'))
})

test('#allow a schema name is refused — it would waive every table in it', async () => {
  const dir = await fixtureDir()
  try {
    // Every Supabase table lives in `public`, so this token used to match the
    // schema segment of every qualified object and turn the whole gate green.
    await assert.rejects(() => lint({ dir, allow: ['public'] }), /is a schema, not an object/)
    // The precise waiver still works, and only on what it names.
    const scoped = await lint({ dir, allow: ['public.secrets'] })
    assert.ok(!scoped.findings.some((f) => f.object === 'public.secrets'))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
