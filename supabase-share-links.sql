create extension if not exists pgcrypto;

create table if not exists public.app_share_links (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  target_table text not null check (target_table in ('ventures', 'projects')),
  target_id text not null,
  target_label text,
  password_hash text,
  created_by text,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

create index if not exists app_share_links_target_idx
  on public.app_share_links (target_table, target_id)
  where revoked_at is null;

create table if not exists public.app_shared_notes (
  id uuid primary key default gen_random_uuid(),
  share_link_id uuid not null references public.app_share_links(id) on delete restrict,
  target_table text not null check (target_table in ('ventures', 'projects')),
  target_id text not null,
  subject text not null,
  content text not null,
  author_role text not null default 'Shared user',
  author_key_hash text not null,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create index if not exists app_shared_notes_target_idx
  on public.app_shared_notes (target_table, target_id, created_at desc)
  where deleted_at is null;

alter table public.app_share_links enable row level security;
alter table public.app_shared_notes enable row level security;

revoke all on public.app_share_links from anon, authenticated;
revoke all on public.app_shared_notes from anon, authenticated;

create or replace function public.app_hash_share_secret(secret text)
returns text
language sql
immutable
strict
set search_path = public, pg_temp
as $$
  select encode(extensions.digest(convert_to(secret, 'UTF8'), 'sha256'), 'hex');
$$;

create or replace function public.create_share_link(
  p_token text,
  p_target_table text,
  p_target_id text,
  p_password text default null,
  p_created_by text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_token text := btrim(coalesce(p_token, ''));
  v_target_table text := btrim(coalesce(p_target_table, ''));
  v_target_id text := btrim(coalesce(p_target_id, ''));
  v_password text := coalesce(p_password, '');
  v_label text;
  v_row public.app_share_links;
begin
  if length(v_token) < 32 then
    raise exception 'Share token is too short';
  end if;

  if v_target_table not in ('ventures', 'projects') then
    raise exception 'Only ventures and projects can be shared';
  end if;

  if v_target_table = 'ventures' then
    select name into v_label from public.ventures where id = v_target_id;
  else
    select name into v_label from public.projects where id = v_target_id;
  end if;

  if v_label is null then
    raise exception 'Shared record was not found';
  end if;

  insert into public.app_share_links (
    token_hash,
    target_table,
    target_id,
    target_label,
    password_hash,
    created_by
  )
  values (
    public.app_hash_share_secret(v_token),
    v_target_table,
    v_target_id,
    v_label,
    case when btrim(v_password) = '' then null else extensions.crypt(v_password, extensions.gen_salt('bf')) end,
    nullif(btrim(coalesce(p_created_by, '')), '')
  )
  returning * into v_row;

  return jsonb_build_object(
    'ok', true,
    'id', v_row.id,
    'targetTable', v_row.target_table,
    'targetLabel', v_row.target_label,
    'hasPassword', v_row.password_hash is not null,
    'createdAt', v_row.created_at
  );
end;
$$;

create or replace function public.get_record_shared_notes(
  p_target_table text,
  p_target_id text
)
returns jsonb
language sql
security definer
set search_path = public, pg_temp
as $$
  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', n.id,
        'subject', n.subject,
        'content', n.content,
        'authorRole', n.author_role,
        'createdAt', n.created_at,
        'canDelete', false
      )
      order by n.created_at desc
    ),
    '[]'::jsonb
  )
  from public.app_shared_notes n
  where n.target_table = btrim(coalesce(p_target_table, ''))
    and n.target_id = btrim(coalesce(p_target_id, ''))
    and n.deleted_at is null;
$$;

create or replace function public.get_shared_bundle(
  p_token text,
  p_password text default null,
  p_author_key text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_token text := btrim(coalesce(p_token, ''));
  v_password text := coalesce(p_password, '');
  v_author_key text := btrim(coalesce(p_author_key, ''));
  v_author_key_hash text := case when v_author_key = '' then null else public.app_hash_share_secret(v_author_key) end;
  v_link public.app_share_links;
  v_target jsonb;
  v_target_name text;
  v_target_venture text;
  v_project_names text[] := array[]::text[];
  v_linked jsonb;
  v_notes jsonb;
begin
  select *
    into v_link
  from public.app_share_links
  where token_hash = public.app_hash_share_secret(v_token)
    and revoked_at is null;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;

  if v_link.password_hash is not null and btrim(v_password) = '' then
    return jsonb_build_object('ok', false, 'requiresPassword', true, 'error', 'password_required');
  end if;

  if v_link.password_hash is not null and v_link.password_hash <> extensions.crypt(v_password, v_link.password_hash) then
    return jsonb_build_object('ok', false, 'requiresPassword', true, 'error', 'invalid_password');
  end if;

  if v_link.target_table = 'ventures' then
    select to_jsonb(v), v.name
      into v_target, v_target_name
    from public.ventures v
    where v.id = v_link.target_id;

    select coalesce(array_agg(p.name), array[]::text[])
      into v_project_names
    from public.projects p
    where p.venture = v_target_name;

    v_linked := jsonb_build_object(
      'ventures', '[]'::jsonb,
      'projects', coalesce((select jsonb_agg(to_jsonb(p) order by p.created_at desc) from public.projects p where p.venture = v_target_name), '[]'::jsonb),
      'tasks', coalesce((select jsonb_agg(to_jsonb(t) order by t.created_at desc) from public.tasks t where t.venture = v_target_name or t.project = any(v_project_names)), '[]'::jsonb),
      'documents', coalesce((select jsonb_agg(to_jsonb(d) order by d.created_at desc) from public.documents d where d.venture = v_target_name or d.project = any(v_project_names)), '[]'::jsonb),
      'assets', coalesce((select jsonb_agg(to_jsonb(a) order by a.created_at desc) from public.assets a where a.venture = v_target_name or a.project = any(v_project_names)), '[]'::jsonb),
      'events', coalesce((select jsonb_agg(to_jsonb(e) order by e.created_at desc) from public.events e where e.venture = v_target_name or e.project = any(v_project_names)), '[]'::jsonb),
      'transactions', coalesce((select jsonb_agg(to_jsonb(tr) order by tr.created_at desc) from public.transactions tr where tr.venture = v_target_name or tr.project = any(v_project_names)), '[]'::jsonb)
    );
  else
    select to_jsonb(p), p.name, p.venture
      into v_target, v_target_name, v_target_venture
    from public.projects p
    where p.id = v_link.target_id;

    v_linked := jsonb_build_object(
      'ventures', coalesce((select jsonb_agg(to_jsonb(v) order by v.created_at desc) from public.ventures v where v.name = v_target_venture), '[]'::jsonb),
      'projects', '[]'::jsonb,
      'tasks', coalesce((select jsonb_agg(to_jsonb(t) order by t.created_at desc) from public.tasks t where t.project = v_target_name), '[]'::jsonb),
      'documents', coalesce((select jsonb_agg(to_jsonb(d) order by d.created_at desc) from public.documents d where d.project = v_target_name), '[]'::jsonb),
      'assets', coalesce((select jsonb_agg(to_jsonb(a) order by a.created_at desc) from public.assets a where a.project = v_target_name), '[]'::jsonb),
      'events', coalesce((select jsonb_agg(to_jsonb(e) order by e.created_at desc) from public.events e where e.project = v_target_name), '[]'::jsonb),
      'transactions', coalesce((select jsonb_agg(to_jsonb(tr) order by tr.created_at desc) from public.transactions tr where tr.project = v_target_name), '[]'::jsonb)
    );
  end if;

  if v_target is null then
    return jsonb_build_object('ok', false, 'error', 'shared_record_missing');
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', n.id,
        'subject', n.subject,
        'content', n.content,
        'authorRole', n.author_role,
        'createdAt', n.created_at,
        'canDelete', v_author_key_hash is not null and n.author_key_hash = v_author_key_hash
      )
      order by n.created_at desc
    ),
    '[]'::jsonb
  )
    into v_notes
  from public.app_shared_notes n
  where n.target_table = v_link.target_table
    and n.target_id = v_link.target_id
    and n.deleted_at is null;

  update public.app_share_links
    set last_used_at = now()
  where id = v_link.id;

  return jsonb_build_object(
    'ok', true,
    'share', jsonb_build_object(
      'targetTable', v_link.target_table,
      'targetLabel', v_link.target_label,
      'hasPassword', v_link.password_hash is not null,
      'createdAt', v_link.created_at
    ),
    'targetTable', v_link.target_table,
    'target', v_target,
    'linked', v_linked,
    'notes', v_notes
  );
end;
$$;

create or replace function public.add_shared_note(
  p_token text,
  p_password text,
  p_author_key text,
  p_subject text,
  p_content text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_token text := btrim(coalesce(p_token, ''));
  v_password text := coalesce(p_password, '');
  v_author_key text := btrim(coalesce(p_author_key, ''));
  v_subject text := btrim(coalesce(p_subject, ''));
  v_content text := btrim(coalesce(p_content, ''));
  v_link public.app_share_links;
  v_note public.app_shared_notes;
begin
  if length(v_author_key) < 32 then
    raise exception 'Note owner key is required';
  end if;

  if v_subject = '' or v_content = '' then
    raise exception 'Subject and content are required';
  end if;

  select *
    into v_link
  from public.app_share_links
  where token_hash = public.app_hash_share_secret(v_token)
    and revoked_at is null;

  if not found then
    raise exception 'Share link is invalid';
  end if;

  if v_link.password_hash is not null and v_link.password_hash <> extensions.crypt(v_password, v_link.password_hash) then
    raise exception 'Share password is invalid';
  end if;

  insert into public.app_shared_notes (
    share_link_id,
    target_table,
    target_id,
    subject,
    content,
    author_role,
    author_key_hash
  )
  values (
    v_link.id,
    v_link.target_table,
    v_link.target_id,
    left(v_subject, 180),
    left(v_content, 5000),
    'Shared user',
    public.app_hash_share_secret(v_author_key)
  )
  returning * into v_note;

  return jsonb_build_object(
    'ok', true,
    'note', jsonb_build_object(
      'id', v_note.id,
      'subject', v_note.subject,
      'content', v_note.content,
      'authorRole', v_note.author_role,
      'createdAt', v_note.created_at,
      'canDelete', true
    )
  );
end;
$$;

create or replace function public.delete_shared_note(
  p_token text,
  p_password text,
  p_author_key text,
  p_note_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_token text := btrim(coalesce(p_token, ''));
  v_password text := coalesce(p_password, '');
  v_author_key text := btrim(coalesce(p_author_key, ''));
  v_link public.app_share_links;
  v_deleted_count integer := 0;
begin
  select *
    into v_link
  from public.app_share_links
  where token_hash = public.app_hash_share_secret(v_token)
    and revoked_at is null;

  if not found then
    raise exception 'Share link is invalid';
  end if;

  if v_link.password_hash is not null and v_link.password_hash <> extensions.crypt(v_password, v_link.password_hash) then
    raise exception 'Share password is invalid';
  end if;

  update public.app_shared_notes
    set deleted_at = now()
  where id = p_note_id
    and share_link_id = v_link.id
    and author_key_hash = public.app_hash_share_secret(v_author_key)
    and deleted_at is null;

  get diagnostics v_deleted_count = row_count;

  return jsonb_build_object('ok', true, 'deleted', v_deleted_count > 0);
end;
$$;

revoke all on function public.create_share_link(text, text, text, text, text) from public;
revoke all on function public.get_record_shared_notes(text, text) from public;
revoke all on function public.get_shared_bundle(text, text, text) from public;
revoke all on function public.add_shared_note(text, text, text, text, text) from public;
revoke all on function public.delete_shared_note(text, text, text, uuid) from public;

grant execute on function public.create_share_link(text, text, text, text, text) to anon, authenticated;
grant execute on function public.get_record_shared_notes(text, text) to anon, authenticated;
grant execute on function public.get_shared_bundle(text, text, text) to anon, authenticated;
grant execute on function public.add_shared_note(text, text, text, text, text) to anon, authenticated;
grant execute on function public.delete_shared_note(text, text, text, uuid) to anon, authenticated;
