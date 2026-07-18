// Report a run to the hosted Airlock account (the paid dashboard).
//
// The CLI stays free forever. But if you set a token (--token or $AIRLOCK_TOKEN),
// it ALSO sends the result up to your Airlock account, so your team gets history,
// trends and alerts across every repo — the things a local run can't be.
//
// Fire-and-forget: reporting NEVER fails your build. No token → nothing is sent.

const DEFAULT_ENDPOINT = 'https://airlock-monitor.vercel.app'

/** Shape the run into the payload the Airlock ingest API accepts. */
export function buildPayload(result, { tool, version }) {
  return {
    tool,
    version,
    // Populated automatically inside GitHub Actions; null when run locally.
    repo: process.env.GITHUB_REPOSITORY || null,
    ref: process.env.GITHUB_REF_NAME || process.env.GITHUB_REF || null,
    sha: process.env.GITHUB_SHA || null,
    passed: !!result.passed,
    problems: result.problems || 0,
    warnings: result.warnings || 0,
    findings: (result.findings || []).map((f) => ({
      rule: f.rule,
      level: f.level || null,
      severity: f.severity,
      file: f.file,
      line: f.line,
      object: f.object,
      detail: f.detail,
    })),
    at: new Date().toISOString(),
  }
}

/**
 * Send a run to the Airlock account. Returns { sent } — always resolves, never throws.
 * @param {object} result  the enriched lint result
 * @param {{tool:string, version:string, token?:string, endpoint?:string, fetchImpl?:Function}} opts
 */
export async function reportRun(result, { tool, version, token, endpoint = DEFAULT_ENDPOINT, fetchImpl = fetch } = {}) {
  if (!token) return { sent: false, reason: 'no token' }
  try {
    const res = await fetchImpl(`${endpoint.replace(/\/$/, '')}/api/ci/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(buildPayload(result, { tool, version })),
    })
    return { sent: res.ok === true || res.status === 200 || res.status === 201, status: res.status }
  } catch (e) {
    return { sent: false, reason: String((e && e.message) || e) }
  }
}
