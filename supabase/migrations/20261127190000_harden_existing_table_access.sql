BEGIN;

-- The current browser client still writes save_data and balance fields.
-- Server-authoritative progression requires a separate trusted combat/reward service.
REVOKE ALL ON TABLE public.profiles FROM PUBLIC, anon;
REVOKE ALL PRIVILEGES (
  id, pilot_id, pilot_name, role, is_banned, ban_reason, credits, uridium,
  xenomit, xp, honor, active_ship_id, company_id, clan_tag, save_data,
  updated_at, created_at
) ON TABLE public.profiles FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.profiles FROM authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.profiles TO authenticated;

DROP POLICY IF EXISTS "Read profiles" ON public.profiles;
CREATE POLICY "Read own profile or admin"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (id = (SELECT auth.uid()) OR (SELECT public.is_admin()));

CREATE OR REPLACE FUNCTION public.get_public_leaderboard(p_limit integer DEFAULT 10)
RETURNS TABLE (
  id uuid,
  pilot_id text,
  pilot_name text,
  xp bigint,
  honor bigint,
  active_ship_id text,
  company_id text,
  clan_tag text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, auth, pg_temp
AS $function$
  SELECT p.id, p.pilot_id, p.pilot_name, p.xp, p.honor,
         p.active_ship_id, p.company_id, p.clan_tag
  FROM public.profiles AS p
  WHERE NOT p.is_banned
  ORDER BY p.xp DESC
  LIMIT LEAST(GREATEST(COALESCE(p_limit, 10), 1), 100);
$function$;

CREATE OR REPLACE FUNCTION public.get_admin_profiles()
RETURNS TABLE (
  id uuid,
  pilot_id text,
  pilot_name text,
  role text,
  is_banned boolean,
  ban_reason text,
  credits bigint,
  uridium bigint,
  xenomit bigint,
  xp bigint,
  honor bigint,
  active_ship_id text,
  company_id text,
  clan_tag text,
  updated_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, auth, pg_temp
AS $function$
  SELECT p.id, p.pilot_id, p.pilot_name, p.role, p.is_banned,
         p.ban_reason, p.credits, p.uridium, p.xenomit, p.xp, p.honor,
         p.active_ship_id, p.company_id, p.clan_tag, p.updated_at
  FROM public.profiles AS p
  WHERE (SELECT public.is_admin())
  ORDER BY p.xp DESC
  LIMIT 100;
$function$;

REVOKE ALL ON FUNCTION public.get_public_leaderboard(integer) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.get_admin_profiles() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_public_leaderboard(integer) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_admin_profiles() TO authenticated;

REVOKE ALL ON TABLE public.global_events FROM PUBLIC, anon;
REVOKE ALL PRIVILEGES (
  id, gold_booty_active, double_xp_active, announcement, updated_at,
  maintenance_active, maintenance_message
) ON TABLE public.global_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.global_events FROM authenticated;
GRANT SELECT, UPDATE ON TABLE public.global_events TO authenticated;

REVOKE ALL ON TABLE public.chat_messages FROM PUBLIC, anon;
REVOKE ALL PRIVILEGES (
  id, user_id, pilot_id, pilot_name, clan_tag, company_id, sector_id,
  message, created_at
) ON TABLE public.chat_messages FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.chat_messages FROM authenticated;
GRANT SELECT, INSERT, DELETE ON TABLE public.chat_messages TO authenticated;
REVOKE ALL ON SEQUENCE public.chat_messages_id_seq FROM PUBLIC, anon;
GRANT USAGE ON SEQUENCE public.chat_messages_id_seq TO authenticated;

DROP POLICY IF EXISTS "Authenticated users can read chat_messages" ON public.chat_messages;
CREATE POLICY "Authenticated users can read chat_messages"
  ON public.chat_messages
  FOR SELECT
  TO authenticated
  USING (true);

DROP POLICY IF EXISTS "Authenticated users can insert chat_messages" ON public.chat_messages;
CREATE POLICY "Authenticated users can insert chat_messages"
  ON public.chat_messages
  FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id = (SELECT auth.uid())
    AND EXISTS (
      SELECT 1
      FROM public.profiles AS p
      WHERE p.id = (SELECT auth.uid())
        AND p.is_banned = false
    )
  );

DROP POLICY IF EXISTS "Admins can delete chat_messages" ON public.chat_messages;
CREATE POLICY "Admins can delete chat_messages"
  ON public.chat_messages
  FOR DELETE
  TO authenticated
  USING (EXISTS (
    SELECT 1
    FROM public.profiles AS p
    WHERE p.id = (SELECT auth.uid())
      AND p.role = 'admin'
  ));

COMMIT;
