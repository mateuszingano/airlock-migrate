// Migration Guard — orchestrates the scan across a folder of migration files.

import { readdir, readFile } from 'node:fs/promises'
import { join, extname, relative } from 'node:path'
import { scanSql, finalizeTables, finalizeDrops } from './rules.mjs'

/** Recursively collect .sql files, sorted (migration order is lexicographic). */
export async function collectSqlFiles(dir) {
  const out = []
  async function walk(d) {
    let entries
    try {
      entries = await readdir(d, { withFileTypes: true })
    } catch {
      return
    }
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const e of entries) {
      const p = join(d, e.name)
      if (e.isDirectory()) await walk(p)
      else if (extname(e.name).toLowerCase() === '.sql') out.push(p)
    }
  }
  await walk(dir)
  return out
}

function short(file, dir) {
  if (!dir) return file.split(/[\\/]/).pop()
  const r = relative(dir, file)
  return r || file
}

/**
 * Lint a set of migration files.
 * @param {{dir?: string, files?: string[], allow?: string[]}} opts
 * @returns {Promise<{files:number, findings:Array, allowed:Array, problems:number, warnings:number, passed:boolean}>}
 */
export async function lint({ dir, files, allow = [] } = {}) {
  const sqlFiles = files || (await collectSqlFiles(dir))

  const events = []
  const droppedPolicies = []
  // Maps, not Sets: they carry WHERE each object was re-created so a drop is only
  // cancelled by a create that comes after it (see finalizeDrops). Positions are
  // made global by offsetting each file's in-text index by its migration order,
  // since files are applied in lexicographic order.
  const recreatedPolicies = new Map()
  const droppedTriggers = []
  const recreatedTriggers = new Map()
  let findings = []

  const FILE_SPAN = 1e9 // any single .sql is far smaller than this
  let fileIndex = 0
  for (const file of sqlFiles) {
    const base = fileIndex++ * FILE_SPAN
    const sql = await readFile(file, 'utf8')
    const res = scanSql(sql, short(file, dir))
    events.push(...res.events) // files are already sorted → events stay in migration order
    droppedPolicies.push(...res.droppedPolicies.map((d) => ({ ...d, pos: base + (d.index ?? 0) })))
    for (const [k, at] of res.recreatedPolicies) {
      const p = base + at
      if (!recreatedPolicies.has(k) || p > recreatedPolicies.get(k)) recreatedPolicies.set(k, p)
    }
    droppedTriggers.push(...res.droppedTriggers.map((d) => ({ ...d, pos: base + (d.index ?? 0) })))
    for (const [k, at] of res.recreatedTriggers) {
      const p = base + at
      if (!recreatedTriggers.has(k) || p > recreatedTriggers.get(k)) recreatedTriggers.set(k, p)
    }
    findings.push(...res.findings)
  }
  findings.push(...finalizeTables(events))
  findings.push(...finalizeDrops(droppedPolicies, recreatedPolicies, droppedTriggers, recreatedTriggers))

  // Allow-list: a token silences a finding when it matches the rule
  // (`rule:drop_trigger`) or appears in the object (a table/policy name).
  // Allow-list matching is by whole IDENTIFIER, not substring.
  //
  // `obj.includes(a)` meant `--allow avatars` also silenced `avatars_secrets`
  // and `user_avatars_private` — three tables muted by one intentional
  // exception, and across rules too. Waving through a deliberately public
  // avatars bucket must not quietly mute a CRITICAL on a secrets table that
  // happens to share a word.
  //
  // Supported forms:
  //   avatars                      → any finding whose object contains the whole
  //                                  identifier `avatars` as a segment
  //   public.avatars               → the qualified name
  //   rule:drop_trigger            → every finding of that rule
  //   rule:create_table_no_rls:avatars → that rule, on that object only
  //   avatars*                     → explicit prefix match (opt-in substring)
  const allowSet = allow.map((a) => a.toLowerCase()).filter(Boolean)
  // A bare `*` matched every segment of every object, so one innocuous-looking
  // glob turned the whole gate green — including the CRITICALs. A kill switch
  // that reads like a wildcard is a trap: someone quoting a shell glob gets a
  // passing build and no protection. Refuse it and say what to write instead.
  for (const token of allowSet) {
    if (/^\*+$/.test(token)) {
      throw new Error(
        `--allow "${token}" would silence every finding and disable the gate entirely. ` +
          `If that is really what you want, delete the migration-guard step instead — a check that always passes is worse than no check. ` +
          `To waive specific things use a name (avatars), a qualified name (public.avatars), a prefix (avatars*), or a rule (rule:drop_trigger).`
      )
    }
  }
  // Identifier segments of an object string: "p on public.avatars_secrets" →
  // ['p', 'public', 'avatars_secrets', 'public.avatars_secrets']
  const segmentsOf = (obj) => {
    const words = obj.split(/[^\w.]+/).filter(Boolean)
    const out = new Set()
    for (const w of words) {
      out.add(w)
      for (const part of w.split('.')) if (part) out.add(part)
    }
    return out
  }
  const matches = (token, f, segs) => {
    if (token === `rule:${f.rule}`) return true
    const scoped = token.match(/^rule:([\w]+):(.+)$/)
    if (scoped) return scoped[1] === f.rule && segs.has(scoped[2])
    // `unparsable` means "this file could not be read, so nothing in it was
    // checked". Its object is a FILE NAME, and file names all end in `sql` — so
    // `--allow sql`, or any token matching a path segment, silenced the one
    // finding that says the gate did not run. Waiving "I could not look" has to
    // be deliberate: only the explicit `rule:unparsable` form does it.
    if (f.rule === 'unparsable') return false
    // `avatars*` is a PREFIX over identifier segments — so it covers
    // `avatars_secrets` but not `user_avatars_private`. Substring semantics here
    // would recreate the very bug this replaced, just behind an opt-in.
    if (token.endsWith('*')) {
      const prefix = token.slice(0, -1)
      return [...segs].some((s) => s.startsWith(prefix))
    }
    return segs.has(token)
  }
  const kept = []
  const allowed = []
  for (const f of findings) {
    const obj = (f.object || '').toLowerCase()
    const segs = segmentsOf(obj)
    const hit = allowSet.some((a) => matches(a, f, segs))
    ;(hit ? allowed : kept).push(f)
  }

  kept.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  const problems = kept.filter((f) => f.severity === 'fail').length
  const warnings = kept.filter((f) => f.severity === 'warn').length

  return { files: sqlFiles.length, findings: kept, allowed, problems, warnings, passed: problems === 0 }
}
