# Migration Guard

**The CI gate for dangerous Supabase/Postgres migrations.** It reads the `.sql`
you are about to ship and fails the build when a change would leak data or break
auth — a table created without RLS, RLS disabled, or a `USING (true)` policy. It
also flags a dropped policy/trigger as a warning (gate on it with
`--fail-on warn`). **No database connection required.**

Supabase leaves Row Level Security **off** for any table you create in SQL, a
migration, or an ORM — the exact path AI-generated schemas take. Migration Guard
catches that in the pull request, before it reaches production.

```bash
npx airlock-migrate                 # lints ./supabase/migrations
npx airlock-migrate ./db/migrations
```

## What it flags

| Rule | Level | Catches |
|------|-------|---------|
| `create_table_no_rls` | fail | a table created without `ENABLE ROW LEVEL SECURITY` |
| `disable_rls` | fail | `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, including the `IF EXISTS` and descendant-`*` spellings |
| `permissive_true` | fail | a policy predicate that reduces to always-true, reachable by a client role — `USING (true)`, `(1=1)`, `(2>1)`, reflexive `(owner_id = owner_id)`, `(1 in (1))`, `length(x) >= 0`, the boolean forms `NOT false`, `true AND true`, `null IS null`, `true IS true`, `1 IS DISTINCT FROM 2`, `1 BETWEEN 0 AND 2`, `coalesce(true,false)`, `CASE WHEN true THEN true END`, `true::boolean`, `(select true)`. Operators are matched by token, so `(1=1)or(x)` counts even without spaces. Covers **both** `CREATE POLICY` and `ALTER POLICY`: widening an existing policy is what an adjustment migration actually does |
| `dynamic_ddl_unanalyzed` | fail / warn | `EXECUTE` of SQL assembled at runtime (`format()`, `\|\|` concatenation, a variable) inside a `DO` block or function body. This gate reads SQL *text*, so it cannot resolve what such a statement targets — it says so instead of reporting the file as clean. **fail** by default (a placeholder defeats any keyword test), stepping down to **warn** only when the statement reads as index/maintenance work (`create/drop index`, `reindex`, `analyze`, `vacuum`, `refresh materialized view`, `comment on`) with no RLS/policy mention |
| `view_bypasses_rls` | warn | a `public` view/matview without `security_invoker = on` — runs as owner, bypasses the RLS beneath it |
| `definer_no_search_path` | warn | a `SECURITY DEFINER` function with no pinned `SET search_path` (search-path hijack → runs as owner) |
| `drop_policy` | warn | a policy dropped and never re-created |
| `drop_trigger` | warn | a trigger dropped and never re-created (how signup logic silently goes missing) |

Only **fail** findings break the build. Warnings are printed for review.

The tautology check evaluates *constant* and *reflexive* predicates statically. A
predicate that is always-true only through a function or the auth token itself
(`is_admin() OR true` with an unknown helper, `auth.uid() IS NOT NULL`) is policy
*logic*, not migration text — run [Airlock RLS](https://shipsealed.com) against the
live database for that.

**No false alarms by design.** Supabase's normal baseline grants (`GRANT ... TO
anon` / `service_role` on every object) are *not* flagged — RLS is the gate
there, not the grant. And a drop that is re-created in the same migration set is
a no-op, so it stays silent. A `USING (true)` policy scoped only to trusted
server roles (`service_role`), or a `RESTRICTIVE` one, isn't flagged either —
only a permissive policy a client role (`anon` / `authenticated` / `public`) can
actually reach.

**Where it deliberately over-flags.** "No false alarms by design" is the goal,
not a guarantee, and there is one place the design chooses noise on purpose:
an `ALTER POLICY … USING (true)` with **no `TO` clause** keeps whatever roles the
policy already had — which may live in an earlier migration or only in the live
database. When this run cannot see that `CREATE`, the finding is raised anyway.
An unprovable role is not a safe role, and staying quiet here would reopen the
exact hole this rule exists to close. If the policy really is server-only, waive
it with `--allow rule:permissive_true:<table>`.

**The allow-list tries not to hand you a kill switch by accident.** A bare `*` is
refused. So is a bare schema name — every Supabase table lives in `public`, so
`--allow public` was a kill switch wearing an ordinary word. And a prefix only
reaches across the schema qualifier when the token itself contains a `.`, so
`public*` and `p*` match table *names*, not every table in the schema. A
schema-wide waiver is still available; you just have to say it out loud:
`--allow public.*`. That is a deliberate off switch, and it is meant to read like
one.

## What it does *not* cover yet

Migration Guard focuses on the RLS / table failure mode. These vectors can also
leak and are **not** flagged yet — review them yourself (or keep the Airlock
Monitor watching production):

- **Views in a non-`public` schema** — `view_bypasses_rls` checks the `public`
  schema, where the client (`anon` / `authenticated`) lives. A view in a custom
  schema exposed to PostgREST via `db-schemas` isn't checked (same boundary as
  the custom-role caveat below).
- **Custom database roles** — a `USING (true)` policy is judged client-reachable
  when it targets `anon` / `authenticated` / `public` (or no `TO` clause). A
  policy scoped only to a *custom* role (`TO my_app_role`) is not flagged, because
  whether that role is client-reachable can't be decided from the SQL alone.
- **Grants to `anon` / `service_role`** — intentionally *not* flagged (RLS is the
  gate; flagging them buries you in noise on a normal Supabase schema).
- **Destructive DDL — the whole category.** `DROP TABLE`, `DROP COLUMN`,
  `TRUNCATE`, `DELETE`/`UPDATE` without `WHERE`, `RENAME`, type narrowing,
  `DROP INDEX`/`DROP CONSTRAINT`, and `CREATE INDEX` without `CONCURRENTLY` all
  pass clean today. Migration Guard targets the RLS/auth failure mode, not data
  loss. If you want a gate on destructive changes, this is not it — yet.
- **Roles beyond the known client set** — `anon`, `authenticated`, `public`,
  `web_anon` and `web_user` are treated as client-reachable (matched as whole
  role segments, so `anon_users` is not swept in). A policy scoped only to some
  other custom role is not flagged, because whether it is client-reachable
  cannot be decided from the SQL alone.
- **Tables in a system schema** (`auth`, `cron`, `vault`, …) are not analyzed —
  they are not yours to police. That skip is now *reported* as a warning rather
  than silently omitted, so a project with its own schema of the same name can
  see that it was passed over.
- **Always-true predicates that need real type or catalog knowledge.** The
  evaluator reduces constants, reflexive equality, `NOT`, `AND`/`OR` (all found
  by token, so `(1=1)or(x)` and `not(1=2)` count without spaces), `IS
  NULL/TRUE/FALSE`, `IS DISTINCT FROM`, `BETWEEN` (incl. `SYMMETRIC`),
  `COALESCE`, a simple `CASE`, casts (incl. multi-word types like `double
  precision`) and a sourceless `(select …)`. It stops where deciding would need
  to know types or resolve a function: an always-true expression built from
  operators it does not model (`'x' || '' = 'x'`, `array_length('{}'::int[],1)
  is null`), a constant-returning built-in it does not special-case (`nullif`,
  `(values (true))`), or a user-defined function that always returns true
  (`using (my_always_true())`).
  A predicate it cannot reduce is left alone rather than guessed at — the
  evaluator is deliberately biased against false alarms on real policies.
- **Dynamic DDL is reported, never resolved.** `dynamic_ddl_unanalyzed` tells you
  a statement was assembled at runtime and could not be read — it does not tell
  you what it did. Because a placeholder defeats any keyword test, the rule
  blocks by default and only steps down to a warning for statements that read as
  index/maintenance work. If your migrations build DDL dynamically on purpose,
  expect to waive it deliberately with `--allow rule:dynamic_ddl_unanalyzed` —
  and know that doing so waives *every* dynamic statement in the run.
- **A function whose header is padded with comments on *both* sides.** A
  `CREATE FUNCTION` body is analyzed when a comment or long whitespace sits
  between `AS` and `$$`, *or* between `create` and `function` — either one alone
  is handled. The one shape that still slips needs **both** at once (~55+ chars
  wedged between `create` and `function` **and** ~22+ between `AS` and `$$`),
  which pushes the keyword past the header window and the `as` past the tail
  window simultaneously, so the body is read as data. No honest migration writes
  it, but it is declared here rather than silently omitted.

What it does **not** do silently: if a file ends *inside* an unterminated
construct (string, block comment, dollar-quote), everything after the opener is
unreadable — so the file is reported as `unparsable` and **fails** the gate. It
is never reported as clean.

What it now covers that the docs used to omit: **`UNLOGGED` and `FOREIGN` tables**
are scanned for missing RLS just like ordinary tables (`TEMP` tables are session-
local, so they're correctly skipped); **`SELECT … INTO <table> FROM …`** (which
creates a table with RLS off, like `CREATE TABLE AS`) is caught too — while the
PL/pgSQL `SELECT … INTO <var>` inside a `DO`/function body (a variable, not a
table) is correctly ignored; a dollar-quoted **data** string (`select $doc$ …
$doc$`) is treated as data, while a `DO` block / function body stays analyzed
(including a dynamic `execute '… disable rls …'` inside it).

## In CI (GitHub Actions)

```yaml
- uses: mateuszingano/airlock-migrate@v1
  with:
    dir: supabase/migrations
    # allow: avatars_public_read,rule:drop_trigger
```

> `@v1` tracks the latest v0.x release. Pin a specific tag (e.g. `@v0.2.0`) to
> lock the version, or use the `npx` form below.

Or run the CLI directly:

```yaml
- run: npx --yes airlock-migrate supabase/migrations
```

## Allow-listing intentional changes

Some exposure is on purpose (a public `avatars` read, a deliberate trigger swap).
Silence a finding by table/policy name or by rule:

```bash
airlock-migrate --allow avatars_public_read,rule:drop_trigger
# or: MIGRATION_GUARD_ALLOW=avatars_public_read airlock-migrate
```

## Exit codes

`0` passed · `1` a dangerous change was found · `2` usage error (no migrations found).

---

Part of [ShipSealed](https://shipsealed.com) — ship apps that don't leak. MIT licensed.
