#!/usr/bin/env node
// Migration Guard — the CI gate for dangerous Supabase/Postgres migrations.
//
// Reads the migration .sql you are about to ship and fails (exit 1) when a
// change would leak data or break auth: a table created without RLS, RLS
// disabled, a permissive USING (true) policy, or a dropped policy/trigger.
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
                     (a table/policy name). Also read from $MIGRATION_GUARD_ALLOW.
  --json             Print the result as JSON (includes level + fix per finding).
  --format <fmt>     text (default) or markdown (AI-ready, with fixes to paste).
  -h, --help         Show this help.
  -v, --version      Show the version.

Rules:
  create_table_no_rls (fail)  table created without ENABLE ROW LEVEL SECURITY
  disable_rls        (fail)   ALTER TABLE ... DISABLE ROW LEVEL SECURITY
  permissive_true    (fail)   CREATE POLICY ... USING (true) / WITH CHECK (true)
  drop_policy        (warn)   a policy dropped and never re-created
  drop_trigger       (warn)   a trigger dropped and never re-created (how signup logic goes missing)

Exit codes: 0 = passed, 1 = dangerous change found, 2 = usage error.`

function splitList(v) {
  return (v || '').split(',').map((s) => s.trim()).filter(Boolean)
}

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = { dir: undefined, json: false, format: 'text', allow: [] }
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-h' || a === '--help') opts.help = true
    else if (a === '-v' || a === '--version') opts.version = true
    else if (a === '--json') opts.json = true
    else if (a === '--format') opts.format = argv[++i]
    else if (a.startsWith('--format=')) opts.format = a.slice('--format='.length)
    else if (a === '--markdown' || a === '--md') opts.format = 'markdown'
    else if (a === '--allow') opts.allow = splitList(argv[++i])
    else if (a.startsWith('--allow=')) opts.allow = splitList(a.slice('--allow='.length))
    else if (a.startsWith('-')) throw new UsageError(`Unknown option: ${a}`)
    else positional.push(a)
  }
  opts.dir = positional[0] || DEFAULT_DIR
  opts.allow = [...splitList(process.env.MIGRATION_GUARD_ALLOW), ...opts.allow]
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

  if (r.passed) {
    const tail = warns.length ? ` ${DIM}(${warns.length} warning(s))${RESET}` : ''
    console.log(`\n${GREEN}Migration check passed.${RESET}${tail} ${DIM}(${r.files} file(s) scanned)${RESET}`)
  } else {
    console.log(`\n${RED}Migration check failed: ${r.problems} dangerous change(s).${RESET}`)
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

  if (opts.json) console.log(JSON.stringify(r, null, 2))
  else if (opts.format === 'markdown') console.log(toMarkdown(r))
  else report(r, opts.dir)

  return r.passed ? 0 : 1
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err instanceof UsageError ? `${err.message}\nRun \`airlock-migrate --help\`.` : err.message)
    process.exit(2)
  })
