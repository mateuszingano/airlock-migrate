// Migration Guard rules — static lint of Supabase/Postgres migration SQL.
//
// No database connection. We read the .sql you are about to ship and flag the
// statements that leak data or break auth BEFORE they merge. This is the wedge
// Atlas closed off (their migrate-lint went paid in Oct 2025) aimed squarely at
// the Supabase failure mode: SQL-created tables ship with RLS OFF by default.
//
// Ethos (inherited from airlock-rls): a false positive is the #1 adoption
// killer. We do NOT flag Supabase's normal baseline grants to anon/service_role
// (RLS is the gate there, not the grant), and a drop that is re-created in the
// same migration set is a no-op, not a warning.
//
// Every finding is { rule, severity: 'fail'|'warn', file, line, object, detail }.

const SYSTEM_SCHEMAS = new Set([
  'auth', 'storage', 'extensions', 'graphql', 'graphql_public', 'realtime',
  'vault', 'pgsodium', 'pgsodium_masks', 'net', 'supabase_functions',
  'supabase_migrations', 'information_schema', 'pg_catalog', 'cron', 'pgbouncer',
])

// Neutralize comments and string literals so their contents can't trip a rule
// (a `--` inside a string must NOT eat the statement after it, and a keyword
// inside a string or comment must not be mistaken for DDL). Newlines are kept so
// reported line numbers stay accurate. Dollar-quoted bodies ($$...$$) are left
// intact on purpose — idempotent migrations put real DDL inside DO blocks.
export function stripComments(sql) {
  let out = ''
  let i = 0
  const n = sql.length
  let inStr = false
  let dollar = null
  while (i < n) {
    const c = sql[i]
    const c2 = sql[i + 1]
    if (dollar) {
      if (c === '$' && sql.startsWith(dollar, i)) { out += dollar; i += dollar.length; dollar = null; continue }
      out += c === '\n' ? '\n' : c
      i++
      continue
    }
    if (inStr) {
      if (c === "'") {
        if (c2 === "'") { out += '  '; i += 2; continue } // escaped '' inside the string
        inStr = false; out += "'"; i++; continue
      }
      out += c === '\n' ? '\n' : ' ' // blank the string contents
      i++
      continue
    }
    if (c === '-' && c2 === '-') {
      while (i < n && sql[i] !== '\n') { out += ' '; i++ } // line comment → spaces
      continue
    }
    if (c === '/' && c2 === '*') {
      out += '  '; i += 2
      while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) { out += sql[i] === '\n' ? '\n' : ' '; i++ }
      if (i < n) { out += '  '; i += 2 }
      continue
    }
    if (c === "'") { inStr = true; out += c; i++; continue }
    if (c === '$') {
      const m = /^\$[A-Za-z_0-9]*\$/.exec(sql.slice(i))
      if (m) { dollar = m[0]; out += m[0]; i += m[0].length; continue }
    }
    out += c
    i++
  }
  return out
}

function lineOf(text, index) {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++
  return line
}

function unquote(s) {
  return s.replace(/"/g, '').trim()
}

// "schema.table" | "table" → normalized key + display (unqualified = public).
function keyOf(ident) {
  const parts = ident.split('.').map(unquote)
  const [schema, table] = parts.length === 2 ? [parts[0], parts[1]] : ['public', parts[0]]
  const s = schema.toLowerCase()
  return { schema: s, table, key: `${s}.${table.toLowerCase()}`, display: `${s}.${table}` }
}

const IDENT = '"?[\\w]+"?(?:\\."?[\\w]+"?)?' // schema.table or table, optionally quoted
const NAME = '"[^"]+"|[\\w]+' // an identifier: a quoted name (may contain spaces) or a bare word

// key for a policy/trigger, scoped to its table so same-named objects don't collide
function objKey(name, tableIdent) {
  return `${keyOf(tableIdent).key}::${unquote(name).toLowerCase()}`
}

// A USING (true) / WITH CHECK (true) policy only leaks if a CLIENT role can reach
// it. It's safe when scoped only to trusted server roles (service_role bypasses
// RLS anyway), and a RESTRICTIVE (true) policy is a no-op restriction, not a grant.
function isClientReachablePermissive(body) {
  if (/\bas\s+restrictive\b/i.test(body)) return false
  const to = /\bto\s+([\w",\s]+?)(?:\s+using\b|\s+with\s+check\b|\s*;|\s*$)/i.exec(body)
  if (!to) return true // no TO clause → defaults to PUBLIC → client-reachable
  return /\b(anon|authenticated|public)\b/i.test(to[1])
}

/**
 * Scan a single migration file.
 * @returns {{
 *   events: Array, (ordered create/enable/drop of tables)
 *   droppedPolicies: Array, recreatedPolicies: Set<string>,
 *   droppedTriggers: Array, recreatedTriggers: Set<string>,
 *   findings: Array
 * }}
 */
export function scanSql(sql, file) {
  const text = stripComments(sql)
  const events = [] // ordered create/enable/drop of tables — order handles drop-then-recreate
  const droppedPolicies = []
  const recreatedPolicies = new Set()
  const droppedTriggers = []
  const recreatedTriggers = new Set()
  const findings = []
  let m

  // CREATE TABLE — an ordered event, keeping the "if not exists" flag
  const reCreate = new RegExp(`create\\s+table\\s+(if\\s+not\\s+exists\\s+)?(${IDENT})`, 'gi')
  while ((m = reCreate.exec(text))) {
    const t = keyOf(m[2])
    if (SYSTEM_SCHEMAS.has(t.schema)) continue
    // A `... PARTITION OF parent` child inherits the parent's RLS — it never
    // gets (or needs) its own ENABLE, so it isn't a table shipped without RLS.
    // Skip it. NOTE: only `PARTITION OF` (the child); a `PARTITION BY` parent
    // comes after the column list and IS a real table that still needs RLS.
    if (/^\s*partition\s+of\b/i.test(text.slice(m.index + m[0].length))) continue
    events.push({ type: 'create', key: t.key, display: t.display, ifne: !!m[1], file, line: lineOf(text, m.index), index: m.index })
  }

  // ALTER TABLE ... ENABLE ROW LEVEL SECURITY
  const reEnable = new RegExp(`alter\\s+table\\s+(?:only\\s+)?(${IDENT})\\s+enable\\s+row\\s+level\\s+security`, 'gi')
  while ((m = reEnable.exec(text))) events.push({ type: 'enable', key: keyOf(m[1]).key, index: m.index })

  // DROP TABLE — resets the table's RLS state, so a later re-create must re-enable
  const reDropTable = new RegExp(`drop\\s+table\\s+(?:if\\s+exists\\s+)?(${IDENT})`, 'gi')
  while ((m = reDropTable.exec(text))) {
    const t = keyOf(m[1])
    if (SYSTEM_SCHEMAS.has(t.schema)) continue
    events.push({ type: 'drop', key: t.key, index: m.index })
  }

  // ALTER TABLE ... DISABLE ROW LEVEL SECURITY → FAIL
  const reDisable = new RegExp(`alter\\s+table\\s+(?:only\\s+)?(${IDENT})\\s+disable\\s+row\\s+level\\s+security`, 'gi')
  while ((m = reDisable.exec(text))) {
    const t = keyOf(m[1])
    findings.push({ rule: 'disable_rls', severity: 'fail', file, line: lineOf(text, m.index), object: t.display, detail: `RLS turned OFF — every row in ${t.display} becomes readable by anyone with the anon key` })
  }

  // CREATE POLICY: record the recreate, and flag USING (true) / WITH CHECK (true)
  const rePolicy = new RegExp(`create\\s+policy\\s+(${NAME})\\s+on\\s+(${IDENT})([\\s\\S]*?);`, 'gi')
  while ((m = rePolicy.exec(text))) {
    recreatedPolicies.add(objKey(m[1], m[2]))
    const body = m[3] || ''
    if (/(using|with\s+check)\s*\(\s*true\s*\)/i.test(body) && isClientReachablePermissive(body)) {
      const t = keyOf(m[2])
      findings.push({ rule: 'permissive_true', severity: 'fail', file, line: lineOf(text, m.index), object: `${unquote(m[1])} on ${t.display}`, detail: `policy uses USING (true) / WITH CHECK (true) reachable by a client role — it lets everyone through, RLS is effectively off` })
    }
  }

  // CREATE TRIGGER: record the recreate (name comes before the ON clause)
  const reCreateTrg = new RegExp(`create\\s+(?:constraint\\s+)?trigger\\s+(${NAME})\\b[\\s\\S]*?\\bon\\s+(${IDENT})`, 'gi')
  while ((m = reCreateTrg.exec(text))) recreatedTriggers.add(objKey(m[1], m[2]))

  // DROP POLICY → candidate warn (only if never re-created — computed in finalize)
  const reDropPol = new RegExp(`drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${NAME})\\s+on\\s+(${IDENT})`, 'gi')
  while ((m = reDropPol.exec(text))) {
    const t = keyOf(m[2])
    droppedPolicies.push({ key: objKey(m[1], m[2]), file, line: lineOf(text, m.index), object: `${unquote(m[1])} on ${t.display}`, table: t.display })
  }

  // DROP TRIGGER → candidate warn (our scar: on_auth_user_created went missing this way)
  const reDropTrg = new RegExp(`drop\\s+trigger\\s+(?:if\\s+exists\\s+)?(${NAME})\\s+on\\s+(${IDENT})`, 'gi')
  while ((m = reDropTrg.exec(text))) {
    const t = keyOf(m[2])
    droppedTriggers.push({ key: objKey(m[1], m[2]), file, line: lineOf(text, m.index), object: `${unquote(m[1])} on ${t.display}`, table: t.display })
  }

  events.sort((a, b) => a.index - b.index)
  return { events, droppedPolicies, recreatedPolicies, droppedTriggers, recreatedTriggers, findings }
}

/**
 * Replay the ordered create/enable/drop events and flag any table whose FINAL
 * state is "exists but RLS off". Because it's ordered: a table dropped and
 * re-created without RLS IS caught (a global set would miss it), while an
 * idempotent `create table if not exists` does not reset a table already tracked.
 */
export function finalizeTables(events) {
  const state = new Map()
  for (const e of events) {
    if (e.type === 'create') {
      if (e.ifne && state.has(e.key)) continue // idempotent re-declare — no-op
      state.set(e.key, { rlsOn: false, file: e.file, line: e.line, display: e.display })
    } else if (e.type === 'enable') {
      const s = state.get(e.key)
      if (s) s.rlsOn = true
    } else if (e.type === 'drop') {
      state.delete(e.key)
    }
  }
  const out = []
  for (const s of state.values()) {
    if (s.rlsOn) continue
    out.push({ rule: 'create_table_no_rls', severity: 'fail', file: s.file, line: s.line, object: s.display, detail: `table created without ENABLE ROW LEVEL SECURITY — Supabase leaves RLS OFF for SQL-created tables, so ${s.display} ships world-readable` })
  }
  return out
}

/**
 * Cross-file: only warn on a NET drop — a policy/trigger dropped and never
 * re-created in the same migration set. Drop-then-recreate is a no-op.
 */
export function finalizeDrops(droppedPolicies, recreatedPolicies, droppedTriggers, recreatedTriggers) {
  const out = []
  for (const d of droppedPolicies) {
    if (recreatedPolicies.has(d.key)) continue
    out.push({ rule: 'drop_policy', severity: 'warn', file: d.file, line: d.line, object: d.object, detail: `policy dropped and not re-created — confirm another policy still protects ${d.table}` })
  }
  for (const d of droppedTriggers) {
    if (recreatedTriggers.has(d.key)) continue
    out.push({ rule: 'drop_trigger', severity: 'warn', file: d.file, line: d.line, object: d.object, detail: `trigger dropped and not re-created — signup / side-effect logic can silently go missing (this is exactly how on_auth_user_created was lost)` })
  }
  return out
}
