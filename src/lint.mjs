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
  const recreatedPolicies = new Set()
  const droppedTriggers = []
  const recreatedTriggers = new Set()
  let findings = []

  for (const file of sqlFiles) {
    const sql = await readFile(file, 'utf8')
    const res = scanSql(sql, short(file, dir))
    events.push(...res.events) // files are already sorted → events stay in migration order
    droppedPolicies.push(...res.droppedPolicies)
    for (const k of res.recreatedPolicies) recreatedPolicies.add(k)
    droppedTriggers.push(...res.droppedTriggers)
    for (const k of res.recreatedTriggers) recreatedTriggers.add(k)
    findings.push(...res.findings)
  }
  findings.push(...finalizeTables(events))
  findings.push(...finalizeDrops(droppedPolicies, recreatedPolicies, droppedTriggers, recreatedTriggers))

  // Allow-list: a token silences a finding when it matches the rule
  // (`rule:drop_trigger`) or appears in the object (a table/policy name).
  const allowSet = allow.map((a) => a.toLowerCase()).filter(Boolean)
  const kept = []
  const allowed = []
  for (const f of findings) {
    const obj = (f.object || '').toLowerCase()
    const hit = allowSet.some((a) => a === `rule:${f.rule}` || obj.includes(a))
    ;(hit ? allowed : kept).push(f)
  }

  kept.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  const problems = kept.filter((f) => f.severity === 'fail').length
  const warnings = kept.filter((f) => f.severity === 'warn').length

  return { files: sqlFiles.length, findings: kept, allowed, problems, warnings, passed: problems === 0 }
}
