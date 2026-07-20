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

/**
 * The printed level for a finding.
 *
 * The severity the ENGINE assigned is the source of truth for how loud this is,
 * because it is what decides the exit code. `LEVELS` only grades *within* that:
 * which build-breaker is critical rather than high.
 *
 * Before, `LEVELS` was a second, independent map with a `|| 'medium'` default,
 * so any rule missing from it printed [MEDIUM] — including `unparsable`, which
 * is a `fail` and DOES break the build. The reader saw a MEDIUM next to a red
 * exit 1. Deriving from severity means a new rule can never be mislabelled by
 * omission again: the worst an unlisted rule gets is a correct-but-coarse label.
 *
 * @param {string} rule
 * @param {'fail'|'warn'} [severity]
 */
export function levelOf(rule, severity) {
  const graded = LEVELS[rule]
  if (severity === 'fail') {
    // A build-breaker is never below 'high', whatever the table says.
    return graded === 'critical' ? 'critical' : 'high'
  }
  if (severity === 'warn') {
    // A warn does not break the build, so it must not wear a build-breaking
    // label — cap it at 'medium'.
    return graded === 'low' ? 'low' : 'medium'
  }
  return graded || 'medium'
}
export function levelLabel(level) {
  return LABEL[level] || String(level).toUpperCase()
}

// "policy \"x\" on public.t" | "public.t" → public.t
function tableOf(object) {
  const m = / on (.+)$/.exec(object || '')
  return requote((m ? m[1] : object || 'public.your_table').trim())
}

// The suggested fix is SQL the reader is meant to paste and RUN, so an
// identifier that needed quotes in the migration needs them here too.
// `alter table public.my other table enable row level security;` is not a fix,
// it is a syntax error wearing one.
function requote(qualified) {
  return qualified
    .split('.')
    .map((part) => (/^[a-z_][a-z0-9_]*$/.test(part) ? part : `"${part.replace(/"/g, '""')}"`))
    .join('.')
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
    case 'dynamic_ddl_unanalyzed':
      return `-- This gate reads SQL text, so DDL assembled at runtime is invisible to it.\n-- Write the statement literally where you can:\n--   alter table public.your_table enable row level security;\n-- If it has to stay dynamic, waive it deliberately:\n--   airlock-migrate --allow rule:dynamic_ddl_unanalyzed`
    default:
      return '-- (no automated fix for this rule)'
  }
}

/** Add { level, fix } to every finding (mutates and returns the result). */
export function enrich(result) {
  result.findings = result.findings.map((f) => ({ ...f, level: levelOf(f.rule, f.severity), fix: fixFor(f) }))
  return result
}

/** AI-ready markdown — paste into Claude / Cursor to apply the fixes. */
export function toMarkdown(result) {
  const fs = [...result.findings].sort((a, b) => (ORDER[levelOf(a.rule, a.severity)] ?? 9) - (ORDER[levelOf(b.rule, b.severity)] ?? 9))
  const counts = fs.reduce((m, f) => ((m[levelOf(f.rule, f.severity)] = (m[levelOf(f.rule, f.severity)] || 0) + 1), m), {})
  const tally = ['critical', 'high', 'medium', 'low'].filter((l) => counts[l]).map((l) => `${counts[l]} ${l}`).join(' · ') || 'none'
  const head = result.passed ? '**PASSED** — nothing dangerous found.' : `**FAILED** — ${result.problems} blocking finding(s).`

  let out = `# Migration Guard report\n\n${head}\n\nSeverity: ${tally}. ${result.files} file(s) scanned.\n`
  if (!fs.length) return out + '\n_No findings._\n'
  out += '\n## Findings\n'
  for (const f of fs) {
    const l = levelOf(f.rule, f.severity)
    out += `\n### ${EMOJI[l]} ${levelLabel(l)} — \`${f.rule}\`\n`
    out += `\`${f.file}:${f.line}\` — ${f.object}\n\n> ${f.detail}\n\n**Fix:**\n\`\`\`sql\n${fixFor(f)}\n\`\`\`\n`
  }
  return out
}
