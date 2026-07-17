// Report layer — turns a finding into something a dev can act on:
// a graded severity, a copy-paste fix, and an AI-ready markdown export.
// Same bar as the Airlock Monitor: we don't just say "you have a problem".

const LEVELS = {
  create_table_no_rls: 'critical', // a world-readable table
  disable_rls: 'critical',
  permissive_true: 'high',
  drop_policy: 'medium',
  drop_trigger: 'medium',
}
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }
const EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' }

export function levelOf(rule) {
  return LEVELS[rule] || 'medium'
}
export function levelLabel(level) {
  return LABEL[level] || String(level).toUpperCase()
}

// "policy \"x\" on public.t" | "public.t" → public.t
function tableOf(object) {
  const m = / on (.+)$/.exec(object || '')
  return (m ? m[1] : object || 'public.your_table').trim()
}

/** The exact SQL / steps to seal this finding. */
export function fixFor(f) {
  const t = tableOf(f.object)
  switch (f.rule) {
    case 'create_table_no_rls':
      return `alter table ${t} enable row level security;\n-- then add a policy scoped to the owner, e.g.:\ncreate policy "owner reads own rows" on ${t}\n  for select using (auth.uid() = user_id);`
    case 'disable_rls':
      return `-- Don't ship with RLS off. Re-enable it:\nalter table ${t} enable row level security;`
    case 'permissive_true':
      return `-- Replace USING (true) with a real predicate, e.g.:\n--   using (auth.uid() = user_id)\n-- If ${t} is meant to be public, allow-list it instead:\n--   airlock-migrate --allow ${t.split('.').pop()}`
    case 'drop_policy':
      return `-- After dropping, confirm another policy still protects ${t},\n-- or recreate the one you meant to replace.`
    case 'drop_trigger':
      return `-- If the trigger is still needed, recreate it in the same migration:\n-- create trigger <name> after insert on ${t}\n--   for each row execute function <fn>();`
    default:
      return '-- (no automated fix for this rule)'
  }
}

/** Add { level, fix } to every finding (mutates and returns the result). */
export function enrich(result) {
  result.findings = result.findings.map((f) => ({ ...f, level: levelOf(f.rule), fix: fixFor(f) }))
  return result
}

/** AI-ready markdown — paste into Claude / Cursor to apply the fixes. */
export function toMarkdown(result) {
  const fs = [...result.findings].sort((a, b) => (ORDER[levelOf(a.rule)] ?? 9) - (ORDER[levelOf(b.rule)] ?? 9))
  const counts = fs.reduce((m, f) => ((m[levelOf(f.rule)] = (m[levelOf(f.rule)] || 0) + 1), m), {})
  const tally = ['critical', 'high', 'medium', 'low'].filter((l) => counts[l]).map((l) => `${counts[l]} ${l}`).join(' · ') || 'none'
  const head = result.passed ? '**PASSED** — nothing dangerous found.' : `**FAILED** — ${result.problems} blocking finding(s).`

  let out = `# Migration Guard report\n\n${head}\n\nSeverity: ${tally}. ${result.files} file(s) scanned.\n`
  if (!fs.length) return out + '\n_No findings._\n'
  out += '\n## Findings\n'
  for (const f of fs) {
    const l = levelOf(f.rule)
    out += `\n### ${EMOJI[l]} ${levelLabel(l)} — \`${f.rule}\`\n`
    out += `\`${f.file}:${f.line}\` — ${f.object}\n\n> ${f.detail}\n\n**Fix:**\n\`\`\`sql\n${fixFor(f)}\n\`\`\`\n`
  }
  return out
}
