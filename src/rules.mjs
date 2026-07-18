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
// reported line numbers stay accurate.
//
// Dollar-quoted bodies are handled by CONTEXT: a DO block or a function body
// (`do $$…$$`, `… as $$…$$`) is real executable DDL and is KEPT intact so it gets
// analyzed (incl. dynamic `execute '…disable rls…'` inside it — a correct catch).
// A dollar-quoted STRING used as DATA (`select $doc$ … $doc$`, a default, an
// inserted value) is BLANKED like a single-quoted string, so a keyword sitting in
// documentation/seed text can't raise a false positive.
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
      if (m) {
        const tag = m[0]
        // Executable only when the token just before the opener is `do` or `as`
        // (a DO block or a function body). Otherwise it's a data string → blank.
        const prev = /([A-Za-z_]+)\s*$/.exec(out)
        const executable = !!prev && (prev[1].toLowerCase() === 'do' || prev[1].toLowerCase() === 'as')
        if (executable) { dollar = tag; out += tag; i += tag.length; continue }
        // Blank the whole dollar-quoted string (preserve newlines for line numbers).
        const close = sql.indexOf(tag, i + tag.length)
        const bodyEnd = close === -1 ? n : close + tag.length
        for (let j = i; j < bodyEnd; j++) out += sql[j] === '\n' ? '\n' : ' '
        i = bodyEnd
        continue
      }
    }
    out += c
    i++
  }
  return out
}

// Build an O(log n) index→line lookup once per file, instead of rescanning from
// the start on every match (which made a single large .sql O(n·matches)).
function makeLineOf(text) {
  const nl = [] // absolute indices of each '\n'
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') nl.push(i)
  return (index) => {
    let lo = 0
    let hi = nl.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (nl[mid] < index) lo = mid + 1
      else hi = mid
    }
    return lo + 1 // newlines strictly before index === line - 1
  }
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
// Ranges of executable dollar bodies (`do $$…$$`, `… as $$…$$`) in the stripped
// text — inside these, `SELECT … INTO x` assigns a PL/pgSQL VARIABLE, not a table.
function executableBodyRanges(text) {
  const ranges = []
  const re = /\b(?:do|as)\s+(\$[A-Za-z_0-9]*\$)/gi
  let m
  while ((m = re.exec(text))) {
    const tag = m[1]
    const bodyStart = m.index + m[0].length
    const close = text.indexOf(tag, bodyStart)
    const end = close === -1 ? text.length : close + tag.length
    ranges.push([m.index, end])
    re.lastIndex = end
  }
  return ranges
}
const inAnyRange = (ranges, i) => ranges.some(([a, b]) => i >= a && i < b)

function isClientReachablePermissive(body) {
  if (/\bas\s+restrictive\b/i.test(body)) return false
  const to = /\bto\s+([\w",\s]+?)(?:\s+using\b|\s+with\s+check\b|\s*;|\s*$)/i.exec(body)
  if (!to) return true // no TO clause → defaults to PUBLIC → client-reachable
  return /\b(anon|authenticated|public)\b/i.test(to[1])
}

// The balanced content of the first `using (...)` / `with check (...)` in a policy
// body (kw is a regex source: 'using' or 'with\\s+check'), or null.
function predicateOf(body, kw) {
  const m = new RegExp(`\\b${kw}\\b`, 'i').exec(body)
  if (!m) return null
  const open = body.indexOf('(', m.index + m[0].length)
  if (open === -1) return null
  let depth = 0
  for (let j = open; j < body.length; j++) {
    if (body[j] === '(') depth++
    else if (body[j] === ')') { depth--; if (depth === 0) return body.slice(open + 1, j) }
  }
  return null
}

// Do fully-balanced outer parens wrap the whole string?
function outerParenWrapsAll(s) {
  if (!s.startsWith('(') || !s.endsWith(')')) return false
  let depth = 0
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') depth++
    else if (s[i] === ')') { depth--; if (depth === 0) return i === s.length - 1 }
  }
  return false
}

// Split a boolean expression on `OR` at paren-depth 0.
function splitTopOr(s) {
  const parts = []
  let depth = 0, last = 0
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') depth++
    else if (s[i] === ')') depth--
    else if (depth === 0 && s.startsWith(' or ', i)) { parts.push(s.slice(last, i)); i += 3; last = i + 1 }
  }
  parts.push(s.slice(last))
  return parts.map((p) => p.trim())
}

// Is this policy predicate a CONSTANT tautology — always true regardless of the
// row? Covers: literal `true`, a constant comparison (`1=1`, `2>1`, `'a'='a'`), a
// REFLEXIVE equality on the identical operand (`owner_id = owner_id`), and a
// top-level OR of those. Deliberately NOT a column-vs-literal (`is_active = true`)
// or a function — those are real predicates. This closes the `USING(1=1)` gap
// without the false positives that fuller policy-logic analysis risks.
function isConstTautology(pred) {
  let s = String(pred).toLowerCase().replace(/\s+/g, ' ').trim()
  while (outerParenWrapsAll(s)) s = s.slice(1, -1).trim()
  if (s === 'true') return true
  const parts = splitTopOr(s)
  if (parts.length > 1) return parts.some(isConstTautology)
  const OPERAND = "'[^']*'|[\\w.]+"
  const refl = new RegExp(`^(${OPERAND})\\s*=\\s*(${OPERAND})$`).exec(s)
  if (refl && refl[1] === refl[2]) return true // owner_id = owner_id
  const cmp = new RegExp(`^(-?\\d+(?:\\.\\d+)?|'[^']*')\\s*(=|<>|!=|<=|>=|<|>)\\s*(-?\\d+(?:\\.\\d+)?|'[^']*')$`).exec(s)
  if (cmp) {
    const [, a, op, b] = cmp
    const aStr = a.startsWith("'"), bStr = b.startsWith("'")
    if (aStr !== bStr) return false // mixed types → don't guess
    const va = aStr ? a : parseFloat(a), vb = bStr ? b : parseFloat(b)
    switch (op) {
      case '=': return va === vb
      case '<>': case '!=': return va !== vb
      case '<': return va < vb
      case '>': return va > vb
      case '<=': return va <= vb
      case '>=': return va >= vb
    }
  }
  // a CONSTANT in a CONSTANT list: `1 in (1)`, `'a' in ('a','b')` (a column left
  // side stays unevaluated — `email in (select …)` is a real scope, not a tautology)
  const inm = new RegExp(`^(${OPERAND})\\s+in\\s*\\((.+)\\)$`).exec(s)
  if (inm) {
    const CONST = /^(?:-?\d+(?:\.\d+)?|'[^']*')$/
    if (!CONST.test(inm[1].trim())) return false
    const list = inm[2].split(',').map((x) => x.trim())
    if (list.length && list.every((x) => CONST.test(x))) return list.includes(inm[1].trim())
    return false
  }
  // a non-negative built-in the comparison can't falsify: `length(x) >= 0`
  const nn = /^(?:length|char_length|character_length|octet_length|bit_length|cardinality)\s*\(.*\)\s*(>=|>|<>|!=)\s*(-?\d+(?:\.\d+)?)$/.exec(s)
  if (nn) {
    const n = parseFloat(nn[2])
    if (nn[1] === '>=') return n <= 0
    if (nn[1] === '>') return n < 0
    if (nn[1] === '<>' || nn[1] === '!=') return n < 0
  }
  return false
}

// Is either the USING or the WITH CHECK predicate an always-true constant tautology?
function hasTautologyPredicate(body) {
  for (const kw of ['using', 'with\\s+check']) {
    const p = predicateOf(body, kw)
    if (p != null && isConstTautology(p)) return true
  }
  return false
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
  const lineAt = makeLineOf(text)
  const events = [] // ordered create/enable/drop of tables — order handles drop-then-recreate
  const droppedPolicies = []
  const recreatedPolicies = new Set()
  const droppedTriggers = []
  const recreatedTriggers = new Set()
  const findings = []
  let m

  // CREATE TABLE — an ordered event, keeping the "if not exists" flag. Also covers
  // UNLOGGED and FOREIGN tables (both ship RLS-off and are client-reachable), but
  // NOT TEMP/TEMPORARY (session-local, never reachable by the API roles) — those
  // simply don't match `create (unlogged|foreign)? table`.
  const reCreate = new RegExp(`create\\s+(?:(unlogged|foreign)\\s+)?table\\s+(if\\s+not\\s+exists\\s+)?(${IDENT})`, 'gi')
  while ((m = reCreate.exec(text))) {
    const t = keyOf(m[3])
    if (SYSTEM_SCHEMAS.has(t.schema)) continue
    // A `... PARTITION OF parent` child inherits the parent's RLS — it never
    // gets (or needs) its own ENABLE, so it isn't a table shipped without RLS.
    // Skip it. NOTE: only `PARTITION OF` (the child); a `PARTITION BY` parent
    // comes after the column list and IS a real table that still needs RLS.
    if (/^\s*partition\s+of\b/i.test(text.slice(m.index + m[0].length))) continue
    events.push({ type: 'create', key: t.key, display: t.display, ifne: !!m[2], file, line: lineAt(m.index), index: m.index })
  }

  // SELECT ... INTO <table> — creates a NEW table (like CREATE TABLE AS) that
  // ships with RLS OFF, same failure mode as CREATE TABLE. Works WITH or WITHOUT
  // a FROM clause. It's a SELECT-INTO (not `INSERT INTO`/`MERGE INTO`) only when
  // its ENCLOSING statement starts with SELECT or WITH — that's the reliable
  // signal, so we don't need a FROM anchor. Skip:
  //  - matches inside a DO/function body (there `SELECT … INTO x` sets a VARIABLE),
  //  - TEMP/TEMPORARY (session-local, not API-reachable — UNLOGGED still needs RLS).
  const bodyRanges = executableBodyRanges(text)
  const reSelectInto = new RegExp(`\\binto\\s+(?:(temp|temporary|unlogged)\\s+)?(?:table\\s+)?(${IDENT})`, 'gi')
  while ((m = reSelectInto.exec(text))) {
    if (inAnyRange(bodyRanges, m.index)) continue // PL/pgSQL SELECT INTO <var>
    const mod = (m[1] || '').toLowerCase()
    if (mod === 'temp' || mod === 'temporary') continue
    // Enclosing statement (from the previous `;`) must be SELECT/WITH — not
    // INSERT INTO / MERGE INTO, which also contain the word `into`.
    const stmt = text.slice(text.lastIndexOf(';', m.index) + 1).replace(/^[\s(]+/, '')
    if (!/^(select|with)\b/i.test(stmt)) continue
    const t = keyOf(m[2])
    if (SYSTEM_SCHEMAS.has(t.schema)) continue
    events.push({ type: 'create', key: t.key, display: t.display, ifne: false, file, line: lineAt(m.index), index: m.index })
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
    findings.push({ rule: 'disable_rls', severity: 'fail', file, line: lineAt(m.index), object: t.display, detail: `RLS turned OFF — every row in ${t.display} becomes readable by anyone with the anon key` })
  }

  // CREATE POLICY: record the recreate, and flag USING (true) / WITH CHECK (true).
  // The body ends at the first `;`, OR (if the `;` was omitted) at the next
  // `create policy` / end of file — so a missing terminator neither drops the
  // policy (false negative) nor bleeds into and mis-flags the following one.
  const rePolicy = new RegExp(
    `create\\s+policy\\s+(${NAME})\\s+on\\s+(${IDENT})([\\s\\S]*?)(?:;|(?=\\bcreate\\s+policy\\b)|$)`,
    'gi'
  )
  while ((m = rePolicy.exec(text))) {
    if (!m[0].trim()) { rePolicy.lastIndex++; continue } // guard against a zero-width match
    recreatedPolicies.add(objKey(m[1], m[2]))
    const body = m[3] || ''
    // `(?:\(\s*)+ … (?:\s*\))+` tolerates ANY nesting/spacing/tabs between the
    // parens — `USING (true)`, `((true))`, `( (true) )`, `(  ( true )  )` all match
    // (comments were already stripped). `\(+` alone missed the spaced variants.
    // `USING (true)` literal, OR a constant tautology (`USING (1=1)`,
    // `USING (owner_id = owner_id)`, `USING (2 > 1)`) that reduces to always-true.
    const litTrue = /(using|with\s+check)\s*(?:\(\s*)+true(?:\s*\))+/i.test(body)
    if ((litTrue || hasTautologyPredicate(body)) && isClientReachablePermissive(body)) {
      const t = keyOf(m[2])
      findings.push({ rule: 'permissive_true', severity: 'fail', file, line: lineAt(m.index), object: `${unquote(m[1])} on ${t.display}`, detail: `policy predicate is always true (USING (true) / (1=1) / (col = col)) and is reachable by a client role — it lets everyone through, RLS is effectively off` })
    }
  }

  // CREATE TRIGGER: record the recreate (name comes before the ON clause)
  const reCreateTrg = new RegExp(`create\\s+(?:constraint\\s+)?trigger\\s+(${NAME})\\b[\\s\\S]*?\\bon\\s+(${IDENT})`, 'gi')
  while ((m = reCreateTrg.exec(text))) recreatedTriggers.add(objKey(m[1], m[2]))

  // DROP POLICY → candidate warn (only if never re-created — computed in finalize)
  const reDropPol = new RegExp(`drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${NAME})\\s+on\\s+(${IDENT})`, 'gi')
  while ((m = reDropPol.exec(text))) {
    const t = keyOf(m[2])
    droppedPolicies.push({ key: objKey(m[1], m[2]), file, line: lineAt(m.index), object: `${unquote(m[1])} on ${t.display}`, table: t.display })
  }

  // DROP TRIGGER → candidate warn (our scar: on_auth_user_created went missing this way)
  const reDropTrg = new RegExp(`drop\\s+trigger\\s+(?:if\\s+exists\\s+)?(${NAME})\\s+on\\s+(${IDENT})`, 'gi')
  while ((m = reDropTrg.exec(text))) {
    const t = keyOf(m[2])
    droppedTriggers.push({ key: objKey(m[1], m[2]), file, line: lineAt(m.index), object: `${unquote(m[1])} on ${t.display}`, table: t.display })
  }

  // CREATE VIEW / MATERIALIZED VIEW in the client-reachable `public` schema. A view
  // runs with its OWNER's rights unless `security_invoker` is on, so it BYPASSES the
  // RLS of the tables beneath it — a public view over a tenant table leaks every row.
  // A materialized view can't enforce RLS at all. Warn (the actual reach depends on a
  // GRANT a static scan can't see), unless the view opts into security_invoker.
  const reView = new RegExp(`create\\s+(?:or\\s+replace\\s+)?(materialized\\s+)?view\\s+(?:if\\s+not\\s+exists\\s+)?(${IDENT})([\\s\\S]*?)\\bas\\b`, 'gi')
  while ((m = reView.exec(text))) {
    const t = keyOf(m[2])
    if (t.schema !== 'public') continue // only the client-reachable schema
    const isMat = !!m[1]
    const invoker = /security_invoker\s*=\s*(?:on|true|yes|1)/i.test(m[3] || '') // PG boolean spellings
    if (isMat || !invoker) {
      findings.push({ rule: 'view_bypasses_rls', severity: 'warn', file, line: lineAt(m.index), object: t.display,
        detail: isMat
          ? `materialized view ${t.display} runs as its owner and cannot enforce RLS — if a client role can read it, it exposes every underlying row. Keep it out of a client-reachable schema, or restrict the grant.`
          : `view ${t.display} runs with its owner's rights (security_invoker off), so it BYPASSES the RLS of the tables beneath it — a client-reachable view over a tenant table leaks every row. Add WITH (security_invoker = on).` })
    }
  }

  // CREATE FUNCTION ... SECURITY DEFINER with no pinned search_path. A definer
  // function executes as its owner; without `SET search_path`, a caller can shadow an
  // unqualified reference through their own search_path and run code as the owner
  // (privilege escalation). Supabase's guidance is to pin `SET search_path = ''`.
  const reDefiner = /create\s+(?:or\s+replace\s+)?function\s+([^;]*?)\bas\b\s*(?:\$[A-Za-z0-9_]*\$|')/gi
  while ((m = reDefiner.exec(text))) {
    const header = m[1]
    if (!/\bsecurity\s+definer\b/i.test(header)) continue
    if (/\bset\s+"?search_path"?\b/i.test(header)) continue // pinned → safe
    const nm = /^\s*("?[\w]+"?(?:\.[\w".]+)?)\s*\(/.exec(header)
    const fn = nm ? unquote(nm[1].split('.').pop()) : 'function'
    findings.push({ rule: 'definer_no_search_path', severity: 'warn', file, line: lineAt(m.index), object: fn,
      detail: `SECURITY DEFINER function ${fn}() has no pinned search_path — it runs as its owner, so a caller can hijack an unqualified name via their own search_path and execute code as the owner. Add SET search_path = ''.` })
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
