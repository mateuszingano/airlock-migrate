-- A migration that ships several leaks. Migration Guard must catch them.

-- 1) table created but RLS never enabled → world-readable (create_table_no_rls)
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  amount numeric not null
);

-- 2) a permissive policy that lets everyone through (permissive_true)
create policy "anyone can read" on public.invoices
  for select using (true);

-- 3) RLS turned off on an existing table (disable_rls)
alter table public.profiles disable row level security;

-- 4) the trigger that fills profiles on signup gets dropped (drop_trigger)
drop trigger if exists on_auth_user_created on auth.users;

-- a comment mentioning "disable row level security" must NOT trip a rule.
