import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://25021475014-arch.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const CLASS_CODES: Record<string, string> = { "VIIA2026": "VII A", "VIIB2026": "VII B" };
const json = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

function randomHex(bytes: number) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return [...data].map(v => v.toString(16).padStart(2, "0")).join("").toUpperCase();
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(v => v.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const url = Deno.env.get("SUPABASE_URL")!;
const secretKeys = Deno.env.get("SUPABASE_SECRET_KEYS");
const secretKey = secretKeys ? JSON.parse(secretKeys).default : Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
if (!url || !secretKey) throw new Error("Supabase server credentials are not configured");
const admin = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false } });

async function issueSession(email: string) {
  const { data, error } = await admin.auth.admin.generateLink({ type: "magiclink", email });
  if (error || !data?.properties?.hashed_token) throw new Error(error?.message || "Token sesi tidak dapat dibuat");
  return data.properties.hashed_token;
}

Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Metode tidak didukung." }, 405);
  try {
    const body = await req.json();
    const action = String(body.action || "");
    const email = String(body.email || "").trim().toLowerCase();
    const classCode = String(body.class_code || "").trim().toUpperCase().replace(/\s+/g, "");
    const className = CLASS_CODES[classCode];
    if (!email || !/^[^\s@]+@[^\s@]+\\.[^\s@]+$/.test(email)) return json({ error: "Alamat email tidak valid." }, 400);
    if (!className) return json({ error: "Kode kelas tidak terdaftar." }, 400);

    if (action === "register") {
      const name = String(body.name || "").trim();
      if (name.length < 2 || name.length > 100) return json({ error: "Nama siswa harus terdiri dari 2–100 karakter." }, 400);
      const recoveryCode = randomHex(24).match(/.{1,8}/g)!.join("-");
      const recoveryHash = await sha256(recoveryCode);
      const randomPassword = randomHex(32) + "aA!9";
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email, password: randomPassword, email_confirm: true,
        user_metadata: { display_name: name, class_code: className },
      });
      if (createError || !created.user) return json({ error: createError?.message || "Akun siswa tidak dapat dibuat." }, 409);
      const { error: insertError } = await admin.from("student_access_credentials").insert({
        user_id: created.user.id, email, class_code: classCode, recovery_hash: recoveryHash,
      });
      if (insertError) {
        await admin.auth.admin.deleteUser(created.user.id);
        return json({ error: "Data pemulihan tidak dapat disimpan: " + insertError.message }, 500);
      }
      const tokenHash = await issueSession(email);
      return json({ token_hash: tokenHash, recovery_code: recoveryCode });
    }

    if (action === "login") {
      const recoveryCode = String(body.recovery_code || "").trim().toUpperCase();
      if (!/^[A-F0-9]{8}(-[A-F0-9]{8}){2}$/.test(recoveryCode)) return json({ error: "Format kode pemulihan tidak sesuai." }, 400);
      const { data: credential, error: lookupError } = await admin.from("student_access_credentials")
        .select("user_id,email,class_code,recovery_hash,failed_attempts,locked_until")
        .eq("email", email).eq("class_code", classCode).maybeSingle();
      if (lookupError) return json({ error: "Data akun belum dapat diperiksa." }, 500);
      if (!credential) return json({ error: "Email, kode kelas, atau kode pemulihan tidak cocok." }, 401);
      if (credential.locked_until && new Date(credential.locked_until).getTime() > Date.now()) {
        return json({ error: "Terlalu banyak percobaan. Coba kembali setelah 15 menit." }, 429);
      }
      const submittedHash = await sha256(recoveryCode);
      if (!safeEqual(submittedHash, credential.recovery_hash)) {
        const attempts = Number(credential.failed_attempts || 0) + 1;
        await admin.from("student_access_credentials").update({
          failed_attempts: attempts >= 8 ? 0 : attempts,
          locked_until: attempts >= 8 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null,
        }).eq("user_id", credential.user_id);
        return json({ error: "Email, kode kelas, atau kode pemulihan tidak cocok." }, 401);
      }
      await admin.from("student_access_credentials").update({ failed_attempts: 0, locked_until: null })
        .eq("user_id", credential.user_id);
      return json({ token_hash: await issueSession(email) });
    }
    return json({ error: "Tindakan tidak dikenal." }, 400);
  } catch (error) {
    console.error("student-access error:", error instanceof Error ? error.message : "unknown");
    return json({ error: "Terjadi kesalahan pada server. Silakan coba kembali." }, 500);
  }
});
