# Migration Guard

**The CI gate for dangerous Supabase/Postgres migrations.** It reads the `.sql`
you are about to ship and fails the build when a change would leak data or break
auth — a table created without RLS, RLS disabled, a `USING (true)` policy, or a
dropped policy/trigger. **No database connection required.**

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
| `disable_rls` | fail | `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` |
| `permissive_true` | fail | `CREATE POLICY ... USING (true)` / `WITH CHECK (true)` |
| `drop_policy` | warn | a policy dropped and never re-created |
| `drop_trigger` | warn | a trigger dropped and never re-created (how signup logic silently goes missing) |

Only **fail** findings break the build. Warnings are printed for review.

**No false alarms by design.** Supabase's normal baseline grants (`GRANT ... TO
anon` / `service_role` on every object) are *not* flagged — RLS is the gate
there, not the grant. And a drop that is re-created in the same migration set is
a no-op, so it stays silent. A `USING (true)` policy scoped only to trusted
server roles (`service_role`), or a `RESTRICTIVE` one, isn't flagged either —
only a permissive policy a client role (`anon` / `authenticated` / `public`) can
actually reach.

## What it does *not* cover yet

Migration Guard focuses on the RLS / table failure mode. These vectors can also
leak and are **not** flagged yet — review them yourself (or keep the Airlock
Monitor watching production):

- **Views / materialized views** over a protected table — a view runs with its
  owner's rights and bypasses RLS unless created `with (security_invoker = on)`.
- **`SECURITY DEFINER` functions** — they run as the definer and can sidestep RLS.
- **Non-literal permissive predicates** — a policy is flagged on the literal
  `USING (true)` / `WITH CHECK (true)`. A tautology written another way
  (`USING (1 = 1)`, `USING (owner_id = owner_id)`) is *not* caught here — for
  full policy-logic analysis, run [Airlock RLS](https://shipsealed.com) against
  the live database.
- **Custom database roles** — a `USING (true)` policy is judged client-reachable
  when it targets `anon` / `authenticated` / `public` (or no `TO` clause). A
  policy scoped only to a *custom* role (`TO my_app_role`) is not flagged, because
  whether that role is client-reachable can't be decided from the SQL alone.
- **Grants to `anon` / `service_role`** — intentionally *not* flagged (RLS is the
  gate; flagging them buries you in noise on a normal Supabase schema).

What it now covers that the docs used to omit: **`UNLOGGED` and `FOREIGN` tables**
are scanned for missing RLS just like ordinary tables (`TEMP` tables are session-
local, so they're correctly skipped); a dollar-quoted **data** string
(`select $doc$ … $doc$`) is treated as data, while a `DO` block / function body
stays analyzed (including a dynamic `execute '… disable rls …'` inside it).

## In CI (GitHub Actions)

```yaml
- uses: mateuszingano/airlock-migrate@v1
  with:
    dir: supabase/migrations
    # allow: avatars_public_read,rule:drop_trigger
```

> `@v1` works once the first release tag is published. Until then, pin `@main`
> or use the `npx` form below.

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
