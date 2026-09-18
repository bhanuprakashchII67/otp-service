create table if not exists public.otp_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  purpose text not null,
  channel text not null check (channel in ('whatsapp', 'email', 'both')),
  destination_hash text not null,
  otp_hash text not null,
  expires_at timestamptz not null,
  attempts integer not null default 0,
  max_attempts integer not null default 5,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists otp_challenges_lookup_idx
  on public.otp_challenges (user_id, purpose, created_at desc);

create index if not exists otp_challenges_expiry_idx
  on public.otp_challenges (expires_at);

alter table public.otp_challenges enable row level security;

revoke all on public.otp_challenges from anon, authenticated;
