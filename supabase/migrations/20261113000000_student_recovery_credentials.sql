-- Private student recovery credentials; accessed only by the student-access Edge Function.
create table if not exists public.student_access_credentials (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  class_code text not null,
  recovery_hash text not null,
  created_at timestamptz not null default now()
);

alter table public.student_access_credentials enable row level security;
revoke all on table public.student_access_credentials from anon, authenticated;
grant select, insert, update on table public.student_access_credentials to service_role;
