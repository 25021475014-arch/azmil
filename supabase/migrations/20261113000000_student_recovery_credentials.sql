-- Private student recovery credentials; accessed only by the student-access Edge Function.
create table if not exists public.student_access_credentials (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  class_code text not null,
  recovery_hash text not null,
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);

alter table public.student_access_credentials enable row level security;
revoke all on table public.student_access_credentials from anon, authenticated;
grant all on table public.student_access_credentials to service_role;


-- Atomically count failed recovery-code attempts and lock the account after 8 failures.
-- This function is callable only by the Edge Function's service role.
create or replace function public.record_student_access_failure(p_user_id uuid)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_locked boolean;
begin
  update public.student_access_credentials
  set
    failed_attempts = case when failed_attempts + 1 >= 8 then 0 else failed_attempts + 1 end,
    locked_until = case
      when failed_attempts + 1 >= 8 then now() + interval '15 minutes'
      else null
    end
  where user_id = p_user_id
    and (locked_until is null or locked_until <= now())
  returning (locked_until is not null and locked_until > now()) into v_locked;

  -- A concurrent failed attempt may have locked the row just before this update.
  -- Re-read the state so the caller consistently receives the lock status.
  if not found then
    select (locked_until is not null and locked_until > now())
      into v_locked
    from public.student_access_credentials
    where user_id = p_user_id;
  end if;

  return coalesce(v_locked, false);
end;
$$;

revoke all on function public.record_student_access_failure(uuid) from public, anon, authenticated;
grant execute on function public.record_student_access_failure(uuid) to service_role;
