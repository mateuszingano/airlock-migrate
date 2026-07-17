-- A migration that does it right. Migration Guard must pass this with no fails.

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid(),
  total numeric not null
);

-- RLS enabled right after create
alter table public.orders enable row level security;

-- a properly scoped policy (not USING (true))
create policy "owner reads own orders" on public.orders
  for select using (owner_id = auth.uid());

create policy "owner writes own orders" on public.orders
  for insert with check (owner_id = auth.uid());
