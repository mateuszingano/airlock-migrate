#!/usr/bin/env node
// Migration Guard — the CI gate for dangerous Supabase/Postgres migrations.
//
// Reads the migration .sql you are about to ship and fails (exit 1) when a
// change would leak data or break auth: a table created without RLS, RLS
// disabled, or a permissive USING (true) policy. A dropped policy/trigger is
// flagged as a warning (gate on it with --fail-on warn).
// No database connection required.
//
// Usage:
//   airlock-migrate                          # lints ./supabase/migrations
//   airlock-migrate ./db/migrations
//   airlock-migrate --allow avatars_public_read,rule:drop_trigger
//   airlock-migrate --json
//
// Exit codes:
//   0  passed — no dangerous change found
//   1  failed — at least one FAIL-level finding
//   2  usage error (no migrations found, bad args)

import { access } from 'node:fs/promises'
import { lint } from '../src/lint.mjs'
import { enrich, toMarkdown, levelLabel } from '../src/report.mjs'
import { reportRun } from '../src/report-ci.mjs'

const RESET = '\x1b[0m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const DIM = '\x1b[2m'

const DEFAULT_DIR = 'supabase/migrations'

const HELP = `Migration Guard — the CI gate for dangerous Supabase/Postgres migrations.

Usage:
  airlock-migrate [DIR] [options]

Arguments:
  DIR                Folder of .sql migrations. Default: ${DEFAULT_DIR}

Options:
  --allow <tokens>   Comma-separated names to silence. A token matches a rule
                     (rule:drop_trigger) or any finding whose object contains it
                     (a whole table/policy name; "name*" for a prefix). Also read
                     from $MIGRATION_GUARD_ALLOW. A bare "*" is refused - it
                     would disable the gate. "unparsable" is waivable only as
                     rule:unparsable, never by a file-name segment.
  --fail-on <level>  What breaks the build: "fail" (default) or "warn". With
                     "warn", the four warn-level rules below can gate too —
                     without it they can only ever be printed, never enforced.
  --json             Print the result as JSON (includes level + fix per finding).
  --format <fmt>     text (default) or markdown (AI-ready, with fixes to paste).
  --token <t>        Send this run to your Airlock account (history, alerts, team
                     dashboard). Free without it. Also read from $AIRLOCK_TOKEN.
  -h, --help         Show this help.
  -v, --version      Show the version.

Rules:
  create_table_no_rls (fail)  table created without ENABLE ROW LEVEL SECURITY
                              (warn outside "public" — not API-reachable by default)
  disable_rls        (fail)   ALTER TABLE ... DISABLE ROW LEVEL SECURITY
  permissive_true    (fail)   CREATE or ALTER POLICY ... USING (true) / WITH CHECK (true)
  unparsable         (fail)   file ends inside an unterminated string/comment/
                              dollar-quote, so the rest of it was never analyzed
  dynamic_ddl_unanalyzed      EXECUTE of SQL assembled at runtime (format(), ||)
                     (fail)   fail by default; warn only for index/maintenance DDL
  drop_policy        (warn)   a policy dropped and never re-created
  drop_trigger       (warn)   a trigger dropped and never re-created (how signup logic goes missing)
  view_bypasses_rls  (warn)   a view without security_invoker reads past the caller's RLS
  definer_no_search_path (warn) SECURITY DEFINER function without a pinned search_path

Exit codes: 0 = passed, 1 = dangerous change found, 2 = usage error.`

function splitList(v) {
  return (v || '').split(',').map((s) => s.trim()).filter(Boolean)
}

class UsageError extends Error {}

function parseArgs(argv) {
  // failOn stays undefined here so the env var can still win in the resolve step
  // below; the literal default ("fail") is applied there, in one place only.
  const opts = { dir: undefined, json: false, format: 'text', allow: [], token: undefined, endpoint: undefined, failOn: undefined }
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-h' || a === '--help') opts.help = true
    else if (a === '-v' || a === '--version') opts.version = true
    else if (a === '--json') opts.json = true
    else if (a === '--format') opts.format = argv[++i]
    else if (a.startsWith('--format=')) opts.format = a.slice('--format='.length)
    else if (a === '--markdown' || a === '--md') opts.format = 'markdown'
    else if (a === '--fail-on') opts.failOn = argv[++i]
    else if (a.startsWith('--fail-on=')) opts.failOn = a.slice('--fail-on='.length)
    else if (a === '--strict') opts.failOn = 'warn' // convenience alias
    else if (a === '--allow') opts.allow = splitList(argv[++i])
    else if (a.startsWith('--allow=')) opts.allow = splitList(a.slice('--allow='.length))
    else if (a === '--token') opts.token = argv[++i]
    else if (a.startsWith('--token=')) opts.token = a.slice('--token='.length)
    else if (a === '--endpoint') opts.endpoint = argv[++i]
    else if (a.startsWith('--endpoint=')) opts.endpoint = a.slice('--endpoint='.length)
    else if (a.startsWith('-')) throw new UsageError(`Unknown option: ${a}`)
    else positional.push(a)
  }
  opts.dir = positional[0] || DEFAULT_DIR
  opts.failOn = (opts.failOn || process.env.MIGRATION_GUARD_FAIL_ON || 'fail').toLowerCase()
  if (opts.failOn !== 'fail' && opts.failOn !== 'warn') {
    throw new UsageError(`Invalid --fail-on "${opts.failOn}". Use "fail" (default) or "warn".`)
  }
  opts.allow = [...splitList(process.env.MIGRATION_GUARD_ALLOW), ...opts.allow]
  opts.token = opts.token || process.env.AIRLOCK_TOKEN
  opts.endpoint = opts.endpoint || process.env.AIRLOCK_ENDPOINT
  return opts
}

async function readVersion() {
  const { readFile } = await import('node:fs/promises')
  try {
    return JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version || '0.0.0'
  } catch {
    return '0.0.0'
  }
}

function printFinding(f, mark, color) {
  const tag = `${color}[${levelLabel(f.level)}]${RESET}`
  console.log(`    ${color}${mark}${RESET} ${tag} ${f.file}:${f.line}  ${f.object} ${DIM}— ${f.detail}${RESET}`)
  for (const line of (f.fix || '').split('\n')) console.log(`        ${DIM}${line}${RESET}`)
}

function report(r, dir) {
  const fails = r.findings.filter((f) => f.severity === 'fail')
  const warns = r.findings.filter((f) => f.severity === 'warn')

  if (fails.length) {
    console.log(`${RED}✗ ${fails.length} dangerous change(s):${RESET}`)
    for (const f of fails) printFinding(f, '✗', RED)
  } else {
    console.log(`${GREEN}✓ No dangerous migrations in "${dir}".${RESET}`)
  }

  if (warns.length) {
    console.log(`${YELLOW}! ${warns.length} warning(s) worth a look:${RESET}`)
    for (const f of warns) printFinding(f, '!', YELLOW)
  }

  if (r.allowed.length) {
    console.log(`${DIM}ℹ ${r.allowed.length} finding(s) allowed by config.${RESET}`)
  }

  if (r.gatePassed) {
    const tail = warns.length ? ` ${DIM}(${warns.length} warning(s))${RESET}` : ''
    console.log(`\n${GREEN}Migration check passed.${RESET}${tail} ${DIM}(${r.files} file(s) scanned)${RESET}`)
    // Say it out loud when warnings exist but can't gate — otherwise a reader
    // assumes "passed" means "nothing worth acting on".
    if (warns.length) {
      console.log(`${DIM}  ${warns.length} warning(s) did not fail the build. Use --fail-on warn to gate on them.${RESET}`)
    }
  } else {
    const what = r.problems ? `${r.problems} dangerous change(s)` : `${warns.length} warning(s) with --fail-on warn`
    console.log(`\n${RED}Migration check failed: ${what}.${RESET}`)
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.help) { console.log(HELP); return 0 }
  if (opts.version) { console.log(await readVersion()); return 0 }

  try {
    await access(opts.dir)
  } catch {
    console.error(`No migrations folder at "${opts.dir}".`)
    console.error(`Pass the path as the first argument, e.g. \`airlock-migrate ./db/migrations\`.`)
    return 2
  }

  const r = enrich(await lint({ dir: opts.dir, allow: opts.allow }))
  if (r.files === 0) {
    console.error(`No .sql files found under "${opts.dir}".`)
    return 2
  }

  // `passed` is the rule-level verdict (no fail-severity findings). `gatePassed`
  // is the build verdict, which --fail-on can widen to include warnings.
  r.gatePassed = opts.failOn === 'warn' ? r.problems === 0 && r.warnings === 0 : r.passed

  if (opts.json) console.log(JSON.stringify(r, null, 2))
  else if (opts.format === 'markdown') console.log(toMarkdown(r))
  else report(r, opts.dir)

  // Paid connector: if a token is set, send the run up to the Airlock account
  // (history/alerts/team). Fire-and-forget — never changes the exit code.
  if (opts.token) {
    const sent = await reportRun(r, { tool: 'airlock-migrate', version: await readVersion(), token: opts.token, endpoint: opts.endpoint })
    if (!opts.json && opts.format !== 'markdown') {
      console.log(sent.sent ? `${DIM}↑ reported to your Airlock account.${RESET}` : `${DIM}↑ Airlock report skipped (${sent.reason || sent.status}).${RESET}`)
    }
  }

  return r.gatePassed ? 0 : 1
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err instanceof UsageError ? `${err.message}\nRun \`airlock-migrate --help\`.` : err.message)
    process.exit(2)
  })
