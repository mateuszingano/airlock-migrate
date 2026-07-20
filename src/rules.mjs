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
//
// `state` (optional, out-param) receives `{ unterminated }` describing the state
// the scanner was still in when it hit EOF. That matters because an unterminated
// construct silently swallows the rest of the file: everything after it is
// blanked, so a real `disable row level security` further down vanishes and the
// gate goes green. A gate must never report "clean" on text it could not read —
// scanSql turns a non-null `unterminated` into a hard `fail`. Kept as an
// out-param so the return type stays a plain string for existing callers.
// Sticky (`y`) so it can be matched AT a position without slicing the string.
const DOLLAR_TAG_RE = /\$[A-Za-z_0-9]*\$/y

export function stripComments(sql, state) {
  // Chunks, not string +=: the lookback below needs to read recently emitted
  // text, and slicing a 1MB cons-string forces V8 to flatten the whole rope on
  // every dollar quote. An array keeps appends O(1) and lets the lookback touch
  // only the last few entries.
  const parts = []
  let i = 0
  const n = sql.length
  let inStr = false
  let dollar = null
  let inBlockComment = false
  // Ranges of EXECUTABLE dollar bodies, emitted by the same decision that keeps
  // them un-blanked. There used to be a second, independent regex
  // (`executableBodyRanges`) that re-derived this from the stripped text, and
  // the two disagreed on one character: this one accepts `do$$` (it tests the
  // statement head), that one required `do\s+$$`. So with no space the body was
  // preserved as code but NOT marked executable, and a PL/pgSQL `SELECT … INTO
  // v` inside it was read as a table creation — a blocking CRITICAL decided by
  // a space. One producer, one source of truth: the duplication is what
  // diverged, so it is gone rather than patched.
  const execRanges = []
  let openRange = null
  // Index in `parts` where the current statement begins (just past the last
  // emitted `;`). Lets the dollar-quote classifier read the statement's opening
  // keyword in O(1) instead of scanning a lookback window.
  let stmtStartPart = 0
  while (i < n) {
    const c = sql[i]
    const c2 = sql[i + 1]
    if (dollar) {
      if (c === '$' && sql.startsWith(dollar, i)) {
        parts.push(dollar)
        i += dollar.length
        dollar = null
        if (openRange) { execRanges.push([openRange[0], i]); openRange = null }
        continue
      }
      parts.push(c === '\n' ? '\n' : c)
      i++
      continue
    }
    if (inStr) {
      if (c === "'") {
        if (c2 === "'") { parts.push('  '); i += 2; continue } // escaped '' inside the string
        inStr = false; parts.push("'"); i++; continue
      }
      parts.push(c === '\n' ? '\n' : ' ') // blank the string contents
      i++
      continue
    }
    if (c === '-' && c2 === '-') {
      while (i < n && sql[i] !== '\n') { parts.push(' '); i++ } // line comment → spaces
      continue
    }
    if (c === '/' && c2 === '*') {
      // Postgres NESTS block comments: /* a /* b */ c */ is one comment, closed
      // by the LAST */. Closing at the first one left `c */` as live SQL, so a
      // block someone commented out to disable it — with a comment already
      // inside — came back as executable and produced a CRITICAL for a table
      // that does not exist. A blocking false alarm, in a product whose README
      // promises "no false alarms by design".
      let depth = 0
      inBlockComment = true
      while (i < n) {
        if (sql[i] === '/' && sql[i + 1] === '*') { depth++; parts.push('  '); i += 2; continue }
        if (sql[i] === '*' && sql[i + 1] === '/') {
          depth--
          parts.push('  '); i += 2
          if (depth === 0) { inBlockComment = false; break }
          continue
        }
        parts.push(sql[i] === '\n' ? '\n' : ' ')
        i++
      }
      continue
    }
    if (c === "'") { inStr = true; parts.push(c); i++; continue }
    if (c === '$') {
      // Sticky match at `i` — do NOT slice. `sql.slice(i)` copied the entire
      // remaining file on every `$` in the input, which is quadratic in the
      // number of dollar quotes and was the last big cost in the measured hang
      // (2.4s of a 2.4s scan on a 946KB migration full of DO blocks).
      DOLLAR_TAG_RE.lastIndex = i
      const m = DOLLAR_TAG_RE.exec(sql)
      if (m) {
        const tag = m[0]
        // Is this an executable body (a DO block / function body) or a data
        // string? Decided from the whole STATEMENT, not the adjacent token.
        //
        // Looking only at the token before `$$` meant `do language plpgsql $$`
        // saw `plpgsql`, concluded "data", and blanked the entire block — so a
        // `disable row level security` inside it vanished and the gate went
        // green. One optional, perfectly valid keyword turned the scanner off.
        // The same held for `do language sql $$` and for function headers with
        // clauses between `AS` and the body.
        //
        // We need two things, and each needs only a few characters:
        //   - does this statement OPEN with `do`?  → its first bytes
        //   - does `as` sit just before the body?  → its last bytes
        // We track where the current statement started (the index in `parts`
        // just after the last emitted `;`), so both are O(1) slices no matter
        // how long the statement is.
        //
        // This replaces a fixed 400-chunk lookback window. That window was a
        // silent cliff: a `create function` header longer than it — a wide
        // argument list, several clauses between `AS` and the body — pushed the
        // opening keyword out of view, the body was classified as DATA and
        // blanked, and every rule inside it went quiet with no signal at all.
        // The window existed for speed (scanning the whole accumulated output
        // once per `$` was 3.4s of a 3.6s scan); anchoring to the statement
        // start keeps that speed without the cliff.
        const stmtHead = parts.slice(stmtStartPart, stmtStartPart + 64).join('')
        const stmtTail = parts.slice(-24).join('')
        const executable =
          // A DO block: the statement OPENS with `do`, whatever comes between it
          // and the body (`do $$`, `do language plpgsql $$`, `do language sql $$`).
          /^\s*do\b/i.test(stmtHead) ||
          // A function body: `AS` always sits immediately before the dollar tag,
          // whether LANGUAGE was declared before or after it.
          /\bas\s*$/i.test(stmtTail)
        if (executable) { dollar = tag; openRange = [i]; parts.push(tag); i += tag.length; continue }
        // Blank the whole dollar-quoted string (preserve newlines for line numbers).
        const close = sql.indexOf(tag, i + tag.length)
        const bodyEnd = close === -1 ? n : close + tag.length
        if (close === -1 && state) state.unterminated = `dollar-quoted string ${tag}`
        for (let j = i; j < bodyEnd; j++) parts.push(sql[j] === '\n' ? '\n' : ' ')
        i = bodyEnd
        continue
      }
    }
    parts.push(c)
    if (c === ';') stmtStartPart = parts.length // a new statement begins after it
    i++
  }
  // An executable body still open at EOF runs to the end of the text — treat it
  // as executable to the end rather than dropping the range, so an unterminated
  // block does not turn its contents back into apparent top-level DDL.
  if (openRange) execRanges.push([openRange[0], n])
  if (state) {
    // Precedence: report the construct we were still inside at EOF. `dollar`
    // (an executable body) and the -1 case above are set at their own sites.
    if (dollar) state.unterminated = `dollar-quoted body ${dollar}`
    else if (inStr) state.unterminated = 'string literal'
    else if (inBlockComment) state.unterminated = 'block comment'
    state.unterminated = state.unterminated || null
    // Emitted in ascending order, which `inAnyRange`'s binary search requires.
    state.executableRanges = execRanges
  }
  return parts.join('')
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

// Remove the OUTER quotes only, and un-double the `""` escape Postgres uses for
// a literal quote inside a quoted identifier. Stripping every `"` blindly
// mangled such a name into a different one.
function unquote(s) {
  const t = String(s).trim()
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1).replace(/""/g, '"')
  }
  return t
}

// Split `schema.table` on the dot SEPARATOR only — a dot inside a quoted
// identifier (`"my.table"`) is part of the name, not a qualifier.
function splitQualified(ident) {
  const parts = []
  let cur = ''
  let inQuotes = false
  for (let i = 0; i < ident.length; i++) {
    const c = ident[i]
    if (c === '"') {
      if (inQuotes && ident[i + 1] === '"') { cur += '""'; i++; continue }
      inQuotes = !inQuotes
      cur += c
      continue
    }
    if (c === '.' && !inQuotes) { parts.push(cur); cur = ''; continue }
    cur += c
  }
  parts.push(cur)
  return parts
}

// "schema.table" | "table" → normalized key + display (unqualified = public).
function keyOf(ident) {
  const parts = splitQualified(ident).map(unquote)
  const [schema, table] = parts.length === 2 ? [parts[0], parts[1]] : ['public', parts[0]]
  const s = schema.toLowerCase()
  return { schema: s, table, key: `${s}.${table.toLowerCase()}`, display: `${s}.${table}` }
}

// schema.table or table, either part optionally quoted.
//
// The quoted alternative is `"[^"]+"`, not `"?[\w]+"?`. With the old shape a
// quoted name stopped at the first character that is not a word character, so
// `create table "my table"` parsed as `public.my`: the CREATE was recorded
// under a name that does not exist, the matching `alter table "my table" enable
// row level security` never matched it, and the result was a blocking CRITICAL
// on a table whose RLS was in fact enabled. Worse, every quoted name sharing a
// first word (`"my table"`, `"my other table"`) collapsed onto ONE key, so a
// real miss on the second could be silenced by the first.
const IDENT = '(?:"[^"]+"|[\\w]+)(?:\\.(?:"[^"]+"|[\\w]+))?'
const NAME = '"[^"]+"|[\\w]+' // an identifier: a quoted name (may contain spaces) or a bare word

// The full head of `ALTER TABLE [ IF EXISTS ] [ ONLY ] name [ * ]`. Both the
// ENABLE and the DISABLE check read from here so the two can never drift: they
// used to spell the prefix out separately, and neither knew about `IF EXISTS`
// or the descendant `*`. Either spelling is ordinary Postgres — a generated
// migration writes `alter table if exists` routinely — so `alter table if
// exists t disable row level security` tore RLS down and the gate printed "No
// dangerous migrations", exit 0.
const ALTER_TABLE = `alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(${IDENT})\\s*\\*?`

// key for a policy/trigger, scoped to its table so same-named objects don't collide
function objKey(name, tableIdent) {
  return `${keyOf(tableIdent).key}::${unquote(name).toLowerCase()}`
}

/**
 * Record that an object was (re)created, KEEPING WHERE.
 *
 * The recreate collections used to be plain Sets, so `finalizeDrops` could only
 * ask "was this ever created?" — not "was it created AFTER the drop?". Any
 * create anywhere silenced any drop of the same object, including a create that
 * came FIRST, where the end state is "object removed". That is exactly the
 * `on_auth_user_created` shape the README uses as its headline scar.
 *
 * A Map is used rather than a Set because both answer `.has()`, so callers and
 * tests that still pass a Set keep working (they simply get the old
 * order-blind behavior).
 */
function recordRecreate(coll, key, index) {
  if (typeof coll?.set === 'function') {
    // keep the LAST create: a drop is only cancelled by a create that follows it
    const prev = coll.get(key)
    if (prev === undefined || index > prev) coll.set(key, index)
  } else if (typeof coll?.add === 'function') {
    coll.add(key)
  }
}

// A USING (true) / WITH CHECK (true) policy only leaks if a CLIENT role can reach
// it. It's safe when scoped only to trusted server roles (service_role bypasses
// RLS anyway), and a RESTRICTIVE (true) policy is a no-op restriction, not a grant.
// Binary search, not `.some()`. The executable ranges are produced in ascending
// order by stripComments, and this is called once per regex match — so a linear scan made it
// O(ranges × matches). On a migration full of DO blocks that was the dominant
// cost (22s at 10k statements) even after the slice fixes.
function inAnyRange(ranges, i) {
  let lo = 0
  let hi = ranges.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    const [a, b] = ranges[mid]
    if (i < a) hi = mid - 1
    else if (i >= b) lo = mid + 1
    else return true
  }
  return false
}

// Roles a request from the public API can arrive as. `web_anon` / `web_user` are
// the names the official PostgREST tutorial uses, and this tool sells itself for
// "Supabase/Postgres" generally — not just Supabase's own role names.
const CLIENT_ROLES = /^(anon|authenticated|public|web_anon|web_user)$/i

function isClientReachablePermissive(body) {
  if (/\bas\s+restrictive\b/i.test(body)) return false
  const to = /\bto\s+([\w",\s]+?)(?:\s+using\b|\s+with\s+check\b|\s*;|\s*$)/i.exec(body)
  if (!to) return true // no TO clause → defaults to PUBLIC → client-reachable
  // Match whole role SEGMENTS, not bare words. `\b(anon)\b` does not match
  // `web_anon`, because `_` is a word character — so every policy written with
  // the PostgREST-tutorial role name was classified as unreachable by a client
  // and passed clean, including `FOR ALL TO web_anon USING (true)`.
  const roles = to[1].split(',').map((r) => r.replace(/"/g, '').trim())
  return roles.some((r) => CLIENT_ROLES.test(r))
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

// Split a boolean expression on the keyword `or` / `and` at paren-depth 0.
//
// The operator is found by TOKEN BOUNDARY, not by surrounding spaces. Matching
// ` or ` meant `(1=1)or(user_id = auth.uid())` — which Postgres accepts and
// which grants every row — was never split, so it read as one unrecognizable
// operand and passed clean. The boundary test is what keeps `order_id` and
// `nordic` from being mistaken for the keyword.
//
// Single-quoted literals are skipped whole (including the `''` escape), so
// `tenant = 'it''s or mine'` stays one operand.
function splitTopOp(s, op) {
  const parts = []
  let depth = 0, last = 0
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === "'") {
      i++
      while (i < s.length) {
        if (s[i] === "'") {
          if (s[i + 1] === "'") i++ // an escaped quote, still inside the literal
          else break
        }
        i++
      }
      continue
    }
    if (c === '(') { depth++; continue }
    if (c === ')') { depth--; continue }
    if (depth !== 0 || !s.startsWith(op, i)) continue
    const before = i === 0 ? '' : s[i - 1]
    const after = s[i + op.length] ?? ''
    if (/[\w$]/.test(before) || /[\w$]/.test(after)) continue // `order_id`, `xor`
    parts.push(s.slice(last, i))
    i += op.length - 1
    last = i + 1
  }
  parts.push(s.slice(last))
  return parts.map((p) => p.trim())
}

// Split a comma-separated argument list at paren-depth 0 (`coalesce(a, f(b,c))`).
function splitArgs(s) {
  const parts = []
  let depth = 0, last = 0
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === "'") {
      i++
      while (i < s.length) {
        if (s[i] === "'") { if (s[i + 1] === "'") i++; else break }
        i++
      }
      continue
    }
    if (c === '(') depth++
    else if (c === ')') depth--
    else if (c === ',' && depth === 0) { parts.push(s.slice(last, i)); last = i + 1 }
  }
  parts.push(s.slice(last))
  return parts.map((p) => p.trim())
}

// Drop `::type` casts that sit outside string literals, so `true::boolean` and
// `1::int = 1::int` reduce like the values they are. Casts inside a literal
// (`name = 'a::b'`) are left alone — that text is data, not syntax.
function stripCasts(s) {
  let out = '', i = 0
  while (i < s.length) {
    const c = s[i]
    if (c === "'") {
      const start = i
      i++
      while (i < s.length) {
        if (s[i] === "'") { if (s[i + 1] === "'") i++; else break }
        i++
      }
      out += s.slice(start, i + 1)
      i++
      continue
    }
    if (c === ':' && s[i + 1] === ':') {
      i += 2
      while (i < s.length && /\s/.test(s[i])) i++
      while (i < s.length && /\w/.test(s[i])) i++ // the type name, and ONLY it —
      // a `/[\s\w]/` loop here would keep eating and swallow `and x` after the cast
      if (s[i] === '(') { // a length/precision: `varchar(10)`, `numeric(10,2)`
        let d = 0
        while (i < s.length) { if (s[i] === '(') d++; else if (s[i] === ')') { d--; if (!d) { i++; break } } i++ }
      }
      continue
    }
    out += c
    i++
  }
  return out
}

// Is this policy predicate a CONSTANT tautology — always true regardless of the
// row? Covers: literal `true`, a constant comparison (`1=1`, `2>1`, `'a'='a'`), a
// REFLEXIVE equality on the identical operand (`owner_id = owner_id`), and a
// top-level OR of those. Deliberately NOT a column-vs-literal (`is_active = true`)
// or a function — those are real predicates. This closes the `USING(1=1)` gap
// without the false positives that fuller policy-logic analysis risks.
function isConstTautology(pred) {
  return constValue(pred) === true
}

// Evaluate a predicate to `true`, `false`, or `null` for "depends on the row —
// don't guess". The three states are what `NOT` and `AND` need: negating an
// unknown is still unknown, so a plain boolean would have had to call every
// unrecognized shape false and `not <unknown>` would come out true — a false
// positive on real predicates. Without this, `using (not false)`,
// `using (true and true)` and `using (null is null)` were all invisible: each
// grants every row, and each shipped green.
function constValue(pred) {
  let s = stripCasts(String(pred).toLowerCase()).replace(/\s+/g, ' ').trim()
  while (outerParenWrapsAll(s)) s = s.slice(1, -1).trim()
  if (s === 'true') return true
  if (s === 'false') return false
  const OPERAND_RE = "'(?:[^']|'')*'|[\\w.]+"

  // Shapes whose own body contains `and` / `or`, so they must be recognized
  // BEFORE the split — otherwise `1 between 0 and 2` is torn into `1 between 0`
  // and `2`, and reads as unknown. Each is anchored to the WHOLE predicate, so
  // a larger expression that merely contains one still falls through to the
  // split below.
  const between = new RegExp(`^(${OPERAND_RE}) (not )?between (${OPERAND_RE}) and (${OPERAND_RE})$`).exec(s)
  if (between) {
    const [, a, neg, lo, hi] = between
    const ge = constValue(`${a} >= ${lo}`)
    const le = constValue(`${a} <= ${hi}`)
    if (ge === null || le === null) return null
    const v = ge && le
    return neg ? !v : v
  }
  const kase = /^case when (.+?) then (.+?)(?: else (.+?))? end$/.exec(s)
  if (kase) {
    const cond = constValue(kase[1])
    if (cond === null) return null
    return cond ? constValue(kase[2]) : kase[3] === undefined ? null : constValue(kase[3])
  }

  // OR before AND: `and` binds tighter, so the top level splits on `or` first.
  const ors = splitTopOp(s, 'or')
  if (ors.length > 1) {
    const vs = ors.map(constValue)
    if (vs.some((v) => v === true)) return true
    return vs.every((v) => v === false) ? false : null
  }
  const ands = splitTopOp(s, 'and')
  if (ands.length > 1) {
    const vs = ands.map(constValue)
    if (vs.some((v) => v === false)) return false
    return vs.every((v) => v === true) ? true : null
  }
  if (s.startsWith('not ')) {
    const inner = constValue(s.slice(4))
    return inner === null ? null : !inner
  }
  const OPERAND = "'[^']*'|[\\w.]+"
  const CONST = /^(?:-?\d+(?:\.\d+)?|'[^']*')$/
  // A scalar subquery with no source (`(select true)`) is just its expression.
  // Anything reading a table stays unknown — that is a real scope, not a constant.
  const scalar = /^select (.+)$/.exec(s)
  if (scalar && !/\b(from|where|join)\b/.test(scalar[1])) return constValue(scalar[1])
  // `coalesce(true, x)` returns its first non-null argument.
  const coal = /^coalesce\s*\((.+)\)$/.exec(s)
  if (coal) {
    for (const arg of splitArgs(coal[1])) {
      if (arg === 'null') continue
      return constValue(arg)
    }
    return null
  }
  // `X is [not] null | true | false | unknown` — decidable only when X itself is.
  // `deleted_at is null` is a real predicate and stays unknown.
  const is = new RegExp(`^(.+?) is (not )?(null|true|false|unknown)$`).exec(s)
  if (is) {
    const [, operand, negated, want] = is
    const lit = operand.trim()
    let v
    if (want === 'null' || want === 'unknown') {
      v = lit === 'null' ? true : CONST.test(lit) || lit === 'true' || lit === 'false' ? false : null
    } else {
      // `x is true` is false (not unknown) when x is null — that is the whole
      // point of the IS form over `=`.
      const inner = lit === 'null' ? 'null' : constValue(lit)
      v = inner === null ? null : inner === 'null' ? false : inner === (want === 'true')
    }
    if (v === null) return null
    return negated ? !v : v
  }
  // `1 is distinct from 2` — null-safe inequality, decidable between literals.
  const distinct = new RegExp(`^(${OPERAND}) is (not )?distinct from (${OPERAND})$`).exec(s)
  if (distinct) {
    const [, a, neg, b] = distinct
    const aNull = a === 'null', bNull = b === 'null'
    let v
    if (aNull || bNull) v = aNull !== bNull
    else if (CONST.test(a) && CONST.test(b)) v = a !== b
    else if (a === b) v = false // `col is distinct from col` is always false
    else return null
    return neg ? !v : v
  }
  const refl = new RegExp(`^(${OPERAND})\\s*=\\s*(${OPERAND})$`).exec(s)
  if (refl && refl[1] === refl[2]) return true // owner_id = owner_id
  const cmp = new RegExp(`^(-?\\d+(?:\\.\\d+)?|'[^']*')\\s*(=|<>|!=|<=|>=|<|>)\\s*(-?\\d+(?:\\.\\d+)?|'[^']*')$`).exec(s)
  if (cmp) {
    const [, a, op, b] = cmp
    const aStr = a.startsWith("'"), bStr = b.startsWith("'")
    if (aStr !== bStr) return null // mixed types → don't guess
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
    if (!CONST.test(inm[1].trim())) return null
    const list = inm[2].split(',').map((x) => x.trim())
    if (list.length && list.every((x) => CONST.test(x))) return list.includes(inm[1].trim())
    return null
  }
  // a non-negative built-in the comparison can't falsify: `length(x) >= 0`
  const nn = /^(?:length|char_length|character_length|octet_length|bit_length|cardinality)\s*\(.*\)\s*(>=|>|<>|!=)\s*(-?\d+(?:\.\d+)?)$/.exec(s)
  if (nn) {
    const n = parseFloat(nn[2])
    if (nn[1] === '>=' && n <= 0) return true
    if ((nn[1] === '>' || nn[1] === '<>' || nn[1] === '!=') && n < 0) return true
    return null // `length(x) >= 5` is a real constraint, not a decided falsehood
  }
  return null
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
  const strip = {}
  const text = stripComments(sql, strip)
  const lineAt = makeLineOf(text)
  const events = [] // ordered create/enable/drop of tables — order handles drop-then-recreate
  const droppedPolicies = []
  const recreatedPolicies = new Map() // key -> in-file index of the LAST create
  const droppedTriggers = []
  const recreatedTriggers = new Map() // key -> in-file index of the LAST create
  const findings = []
  let m

  // The file ended mid-construct, so everything after the opener was blanked and
  // never analyzed. Fail loudly instead of reporting the (necessarily empty)
  // result as clean — otherwise the more broken the file, the greener the gate.
  if (strip.unterminated) {
    findings.push({
      rule: 'unparsable',
      severity: 'fail',
      file,
      line: 1,
      object: file,
      detail: `unterminated ${strip.unterminated} — the rest of the file could not be analyzed`,
      fix: `Close the ${strip.unterminated}. Until it is closed, everything after it is invisible to the guard, so this file is NOT covered by any rule.`,
    })
  }

  // CREATE TABLE — an ordered event, keeping the "if not exists" flag. Also covers
  // UNLOGGED and FOREIGN tables (both ship RLS-off and are client-reachable), but
  // NOT TEMP/TEMPORARY (session-local, never reachable by the API roles) — those
  // simply don't match `create (unlogged|foreign)? table`.
  const reCreate = new RegExp(`create\\s+(?:(unlogged|foreign)\\s+)?table\\s+(if\\s+not\\s+exists\\s+)?(${IDENT})`, 'gi')
  while ((m = reCreate.exec(text))) {
    const t = keyOf(m[3])
    if (SYSTEM_SCHEMAS.has(t.schema)) {
      // SYSTEM_SCHEMAS is a fixed list, so a project that legitimately creates a
      // table in `auth`, `cron` or `vault` — its own schema that happens to
      // share a name, or a real table added to Supabase's — disappeared from the
      // analysis entirely. Skipping is still right (these are not the client's
      // tables to police), but a skip must be VISIBLE: a gate that silently
      // omits part of its input reads as if it checked everything.
      findings.push({
        rule: 'skipped_system_schema',
        severity: 'warn',
        file,
        line: lineAt(m.index),
        object: t.display,
        detail: `table created in the system schema "${t.schema}" — not analyzed. If this is your own schema that happens to share the name, its RLS is NOT being checked.`,
      })
      continue
    }
    // A `... PARTITION OF parent` child inherits the parent's RLS — it never
    // gets (or needs) its own ENABLE, so it isn't a table shipped without RLS.
    // Skip it. NOTE: only `PARTITION OF` (the child); a `PARTITION BY` parent
    // comes after the column list and IS a real table that still needs RLS.
    if (/^\s*partition\s+of\b/i.test(text.slice(m.index + m[0].length))) continue
    events.push({ type: 'create', key: t.key, display: t.display, schema: t.schema, ifne: !!m[2], file, line: lineAt(m.index), index: m.index })
  }

  // Dynamic DDL — `execute` inside a DO block / function body whose SQL is
  // ASSEMBLED at runtime (`format(...)`, `||` concatenation, a variable). The
  // rules above read the statement text literally, so they catch
  // `execute 'alter table public.a disable row level security'` and miss every
  // spelling where the dangerous part is built: `format('alter table %I disable
  // row level security', t)` and `'alter table ' || t || ' disable …'` both tore
  // RLS down while the gate printed "No dangerous migrations", exit 0. We cannot
  // resolve the object here — but reporting "I could not read this" is the one
  // honest answer, and it is the answer a gate owes.
  const reExecute = /\bexecute\s+/gi
  while ((m = reExecute.exec(text))) {
    if (!inAnyRange(strip.executableRanges, m.index)) continue // top-level `execute` is not PL/pgSQL
    const semi = text.indexOf(';', m.index)
    const arg = text.slice(m.index + m[0].length, semi === -1 ? text.length : semi).trim()
    // `execute function f()` / `execute procedure f()` is a TRIGGER clause, not
    // dynamic SQL.
    if (/^(function|procedure)\b/i.test(arg)) continue
    // A single plain literal is fully analyzable, and the rules above already
    // read it — no gap to report.
    if (/^'[^']*'$/.test(arg)) continue
    if (!arg) continue
    // Read the fragment with its seams removed: `format(`, the literal quotes
    // and the `||` joins. Testing the raw text let one splice walk out —
    // `'disable row' || ' level security'` never contains the phrase, so it was
    // graded a warn and warns do not gate: RLS came down, exit 0.
    const seamless = arg
      .replace(/^format\s*\(/i, ' ')
      .replace(/\|\||'/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
    // Default is FAIL, and that is the point: this gate reads SQL text, so a
    // statement assembled at runtime is text it cannot read. Grading the unknown
    // as a warn meant the honest answer ("I could not check this") did not gate,
    // which is the same disease as reporting an unreadable file clean. A
    // placeholder alone defeats any keyword test — `format('… row level %s',
    // 'security')` — so the burden runs the other way: stay loud unless the
    // statement is visibly one of the operations that cannot touch RLS.
    const HARMLESS = /^(create\s+(unique\s+)?index|drop\s+index|reindex|analyze|vacuum|refresh\s+materialized\s+view|comment\s+on)\b/i
    const RLS_WORDS = /row\s+level\s+security|\bpolicy\b|\bgrant\b|\brevoke\b|\bowner\b/i
    const harmless = HARMLESS.test(seamless) && !RLS_WORDS.test(seamless)
    const oneLine = arg.replace(/\s+/g, ' ').slice(0, 80)
    findings.push({
      rule: 'dynamic_ddl_unanalyzed',
      severity: harmless ? 'warn' : 'fail',
      file,
      line: lineAt(m.index),
      object: file,
      detail: harmless
        ? `dynamic DDL built at runtime was not analyzed — it reads as an index/maintenance statement, so it is reported rather than blocking: \`${oneLine}\``
        : `dynamic DDL built at runtime could not be analyzed — the statement is assembled from fragments, so this gate cannot tell what it targets or whether it touches RLS: \`${oneLine}\``,
    })
  }

  // SELECT ... INTO <table> — creates a NEW table (like CREATE TABLE AS) that
  // ships with RLS OFF, same failure mode as CREATE TABLE. Works WITH or WITHOUT
  // a FROM clause. It's a SELECT-INTO (not `INSERT INTO`/`MERGE INTO`) only when
  // its ENCLOSING statement starts with SELECT or WITH — that's the reliable
  // signal, so we don't need a FROM anchor. Skip:
  //  - matches inside a DO/function body (there `SELECT … INTO x` sets a VARIABLE),
  //  - TEMP/TEMPORARY (session-local, not API-reachable — UNLOGGED still needs RLS).
  // Emitted by stripComments itself — the one place that decides what counts as
  // an executable body. See the note on `execRanges` there.
  const bodyRanges = strip.executableRanges
  const reSelectInto = new RegExp(`\\binto\\s+(?:(temp|temporary|unlogged)\\s+)?(?:table\\s+)?(${IDENT})`, 'gi')
  while ((m = reSelectInto.exec(text))) {
    if (inAnyRange(bodyRanges, m.index)) continue // PL/pgSQL SELECT INTO <var>
    const mod = (m[1] || '').toLowerCase()
    if (mod === 'temp' || mod === 'temporary') continue
    // Enclosing statement (from the previous `;`) must be SELECT/WITH — not
    // INSERT INTO / MERGE INTO, which also contain the word `into`.
    // Slice only up to the match, never to end-of-file. The old form
    // (`text.slice(start)`) copied the ENTIRE remaining file on every match, so
    // a big migration went quadratic: 18.4s at 628KB, over 2 minutes at ~1MB —
    // a CI job hung by a large `supabase db dump`. We just need the head of the
    // statement to tell SELECT/WITH from INSERT INTO / MERGE INTO, so the
    // interval [previous `;`, match] is both sufficient and bounded.
    const stmtStart = text.lastIndexOf(';', m.index) + 1
    const stmt = text.slice(stmtStart, m.index).replace(/^[\s(]+/, '')
    if (!/^(select|with)\b/i.test(stmt)) continue
    const t = keyOf(m[2])
    if (SYSTEM_SCHEMAS.has(t.schema)) continue
    events.push({ type: 'create', key: t.key, display: t.display, schema: t.schema, ifne: false, file, line: lineAt(m.index), index: m.index })
  }

  // ALTER TABLE ... ENABLE ROW LEVEL SECURITY
  const reEnable = new RegExp(`${ALTER_TABLE}\\s+enable\\s+row\\s+level\\s+security`, 'gi')
  while ((m = reEnable.exec(text))) events.push({ type: 'enable', key: keyOf(m[1]).key, index: m.index })

  // DROP TABLE — resets the table's RLS state, so a later re-create must re-enable
  const reDropTable = new RegExp(`drop\\s+table\\s+(?:if\\s+exists\\s+)?(${IDENT})`, 'gi')
  while ((m = reDropTable.exec(text))) {
    const t = keyOf(m[1])
    if (SYSTEM_SCHEMAS.has(t.schema)) continue
    events.push({ type: 'drop', key: t.key, index: m.index })
  }

  // ALTER TABLE ... DISABLE ROW LEVEL SECURITY → FAIL
  const reDisable = new RegExp(`${ALTER_TABLE}\\s+disable\\s+row\\s+level\\s+security`, 'gi')
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
  // Remember each CREATE's body so a later ALTER POLICY with no TO clause can
  // inherit the roles it was created with.
  const createPolicyBodies = new Map()
  while ((m = rePolicy.exec(text))) {
    if (!m[0].trim()) { rePolicy.lastIndex++; continue } // guard against a zero-width match
    recordRecreate(recreatedPolicies, objKey(m[1], m[2]), m.index)
    const body = m[3] || ''
    createPolicyBodies.set(objKey(m[1], m[2]), body)
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

  // ALTER POLICY: the same leak, written as an edit instead of a creation.
  //
  // This was invisible for every release: only `create policy` had a regex, so
  // `ALTER POLICY p ON t USING (true)` — a real, complete tenant leak — exited 0
  // under "No dangerous migrations", on the very rule the README leads with.
  // And loosening an existing policy is precisely what an adjustment migration
  // does; nobody drops and recreates a policy to widen it.
  //
  // Roles: ALTER POLICY has no mandatory TO clause. When it omits one it keeps
  // whatever the policy already had, which lives in a CREATE we may not be able
  // to see (an earlier migration, or the live database). So: use this
  // statement's own TO when it has one, else the TO of a CREATE POLICY for the
  // same object in this run, else flag it. Staying silent because we cannot
  // prove reachability would reopen the hole for the common case — an ALTER on
  // its own in a file, which is exactly what the leak looks like.
  const reAlterPolicy = new RegExp(
    `alter\\s+policy\\s+(${NAME})\\s+on\\s+(${IDENT})([\\s\\S]*?)(?:;|(?=\\balter\\s+policy\\b)|(?=\\bcreate\\s+policy\\b)|$)`,
    'gi'
  )
  while ((m = reAlterPolicy.exec(text))) {
    if (!m[0].trim()) { reAlterPolicy.lastIndex++; continue }
    const body = m[3] || ''
    const litTrue = /(using|with\s+check)\s*(?:\(\s*)+true(?:\s*\))+/i.test(body)
    if (!litTrue && !hasTautologyPredicate(body)) continue
    // Own TO clause wins; otherwise inherit from the CREATE in this same run.
    const hasOwnTo = /\bto\s+[\w",\s]+?(?:\s+using\b|\s+with\s+check\b|\s*;|\s*$)/i.test(body)
    const inherited = hasOwnTo ? null : createPolicyBodies.get(objKey(m[1], m[2]))
    const reachable = isClientReachablePermissive(hasOwnTo ? body : inherited ?? body)
    if (!reachable) continue
    const t = keyOf(m[2])
    findings.push({
      rule: 'permissive_true',
      severity: 'fail',
      file,
      line: lineAt(m.index),
      object: `${unquote(m[1])} on ${t.display}`,
      detail:
        `ALTER POLICY loosens the predicate to always true (USING (true) / (1=1) / (col = col))` +
        (inherited
          ? ' on a policy this migration set creates for a client role'
          : hasOwnTo
            ? ' and is reachable by a client role'
            : ' — this ALTER carries no TO clause, so it keeps the roles the policy already had, which this migration set cannot see. Flagged because an unprovable role is not a safe role') +
        ' — it lets everyone through, RLS is effectively off',
    })
  }

  // CREATE TRIGGER: record the recreate (name comes before the ON clause)
  // `[^;]*?` instead of `[\s\S]*?`: a trigger's ON clause is always inside the
  // SAME statement, so there is no reason to let the engine scan to end-of-file
  // looking for one. It did, on every `create trigger` that lacked an ON — which
  // made a big file quadratic (1.2s at 20k statements, and it compounds).
  const reCreateTrg = new RegExp(`create\\s+(?:constraint\\s+)?trigger\\s+(${NAME})\\b[^;]{0,2000}?\\bon\\s+(${IDENT})`, 'gi')
  while ((m = reCreateTrg.exec(text))) recordRecreate(recreatedTriggers, objKey(m[1], m[2]), m.index)

  // DROP POLICY → candidate warn (only if never re-created — computed in finalize)
  const reDropPol = new RegExp(`drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${NAME})\\s+on\\s+(${IDENT})`, 'gi')
  while ((m = reDropPol.exec(text))) {
    const t = keyOf(m[2])
    droppedPolicies.push({ key: objKey(m[1], m[2]), index: m.index, file, line: lineAt(m.index), object: `${unquote(m[1])} on ${t.display}`, table: t.display })
  }

  // DROP TRIGGER → candidate warn (our scar: on_auth_user_created went missing this way)
  const reDropTrg = new RegExp(`drop\\s+trigger\\s+(?:if\\s+exists\\s+)?(${NAME})\\s+on\\s+(${IDENT})`, 'gi')
  while ((m = reDropTrg.exec(text))) {
    const t = keyOf(m[2])
    droppedTriggers.push({ key: objKey(m[1], m[2]), index: m.index, file, line: lineAt(m.index), object: `${unquote(m[1])} on ${t.display}`, table: t.display })
  }

  // CREATE VIEW / MATERIALIZED VIEW in the client-reachable `public` schema. A view
  // runs with its OWNER's rights unless `security_invoker` is on, so it BYPASSES the
  // RLS of the tables beneath it — a public view over a tenant table leaks every row.
  // A materialized view can't enforce RLS at all. Warn (the actual reach depends on a
  // GRANT a static scan can't see), unless the view opts into security_invoker.
  // Same reasoning as the trigger regex: the `AS` of a CREATE VIEW belongs to the
  // same statement. Unbounded, a `create view` with no `AS` scanned the whole
  // rest of the file — 18.4s on a 628KB migration, the worst measured hang.
  const reView = new RegExp(`create\\s+(?:or\\s+replace\\s+)?(materialized\\s+)?view\\s+(?:if\\s+not\\s+exists\\s+)?(${IDENT})([^;]{0,2000}?)\\bas\\b`, 'gi')
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
  // Bounded like the view and trigger regexes. This one was missed in that pass,
  // and it is the same bug in the same class: a `create function` with no `AS`
  // and no `;` scans to end-of-file on every match. Measured on the otherwise
  // fixed code: 10k=1.6s · 20k=6.8s · 40k=25s · 80k=**107s** — still 4x per
  // doubling. A function header longer than 2000 characters does not exist in
  // practice, and if one did, missing it is far better than hanging CI.
  //
  // BOTH clauses can sit on EITHER side of the body. Postgres accepts
  // `... SECURITY DEFINER AS $$…$$ LANGUAGE sql` and
  // `... AS $$…$$ LANGUAGE sql SECURITY DEFINER SET search_path = ''`.
  // Testing only the pre-`AS` header got this wrong in both directions:
  //   - a definer declared AFTER the body was invisible (a false NEGATIVE — and
  //     trailing is the order Supabase's own generator emits), and
  //   - a `SET search_path` declared after the body was not counted as pinned,
  //     so a correctly-hardened function was warned about (a false alarm, in a
  //     product whose README promises none by design).
  // So we read the clauses from the whole statement: the header plus the tail
  // between the end of the body and the terminating `;`.
  const reDefiner = /create\s+(?:or\s+replace\s+)?function\s+([^;]{0,2000}?)\bas\b\s*(\$[A-Za-z0-9_]*\$|')/gi
  while ((m = reDefiner.exec(text))) {
    const header = m[1]
    const opener = m[2]
    // Walk past the body so its contents can never be mistaken for clauses.
    const bodyStart = m.index + m[0].length
    const close = text.indexOf(opener, bodyStart)
    let tail = ''
    if (close !== -1) {
      const afterBody = close + opener.length
      const semi = text.indexOf(';', afterBody)
      tail = text.slice(afterBody, semi === -1 ? text.length : semi)
      // Don't let the scan run away if the statement is unterminated.
      if (tail.length > 2000) tail = tail.slice(0, 2000)
    }
    const clauses = `${header} ${tail}`
    if (!/\bsecurity\s+definer\b/i.test(clauses)) continue
    if (/\bset\s+"?search_path"?\b/i.test(clauses)) continue // pinned → safe
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
      // `schema` is carried through so the severity below can tell a public
      // (API-reachable) table from one in a project-private schema.
      state.set(e.key, { rlsOn: false, file: e.file, line: e.line, display: e.display, schema: e.schema || String(e.key).split('.')[0] })
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
    // Only a table in `public` is reachable by the API by default. A table in a
    // schema the project created (`private`, `internal`) is NOT exposed unless
    // that schema is added to PostgREST's `db-schemas` — and "hide internal
    // tables in a private schema" is Supabase's own documented recommendation.
    // Reporting those as CRITICAL broke the build of people who followed the
    // official advice: a blocking false alarm, in a product whose README leads
    // with "no false alarms by design". Downgrade to a warn with honest wording.
    const isPublic = s.schema === 'public'
    out.push({
      rule: 'create_table_no_rls',
      severity: isPublic ? 'fail' : 'warn',
      file: s.file,
      line: s.line,
      object: s.display,
      detail: isPublic
        ? `table created without ENABLE ROW LEVEL SECURITY — Supabase leaves RLS OFF for SQL-created tables, so ${s.display} ships world-readable`
        : `table created without ENABLE ROW LEVEL SECURITY in schema "${s.schema}" — only client-reachable if that schema is exposed via PostgREST db-schemas. Enable RLS anyway if it ever might be.`,
    })
  }
  return out
}

/**
 * Cross-file: only warn on a NET drop — a policy/trigger dropped and never
 * re-created in the same migration set. Drop-then-recreate is a no-op.
 */
export function finalizeDrops(droppedPolicies, recreatedPolicies, droppedTriggers, recreatedTriggers) {
  // A drop is only cancelled by a create that comes AFTER it. When the recreate
  // collection is a Map (the real pipeline), compare positions; when it's a Set
  // (a direct caller or an older test), fall back to mere presence.
  const cancelled = (coll, d) => {
    if (!coll?.has(d.key)) return false
    if (typeof coll.get !== 'function' || d.pos == null) return true
    const at = coll.get(d.key)
    return at != null && at > d.pos
  }
  const out = []
  for (const d of droppedPolicies) {
    if (cancelled(recreatedPolicies, d)) continue
    out.push({ rule: 'drop_policy', severity: 'warn', file: d.file, line: d.line, object: d.object, detail: `policy dropped and not re-created — confirm another policy still protects ${d.table}` })
  }
  for (const d of droppedTriggers) {
    if (cancelled(recreatedTriggers, d)) continue
    out.push({ rule: 'drop_trigger', severity: 'warn', file: d.file, line: d.line, object: d.object, detail: `trigger dropped and not re-created — signup / side-effect logic can silently go missing (this is exactly how on_auth_user_created was lost)` })
  }
  return out
}
