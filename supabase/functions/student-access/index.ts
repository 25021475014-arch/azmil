import { createClient } from "npm:@supabase/supabase-js@2";
import {
  CLASS_CODES, formatRecoveryCode, isValidEmail, isValidRecoveryCode,
  isValidStudentName, normalizeClassCode, normalizeEmail, safeEqual,
} from "./logic.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://25021475014-arch.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
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

const url = Deno.env.get("SUPABASE_URL")!;
const secretKeys = Deno.env.get("SUPABASE_SECRET_KEYS");
const secretKey = secretKeys ? JSON.parse(secretKeys).default : Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
if (!url || !secretKey) throw new Error("Supabase server credentials are not configured");
const admin = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false } });

async function issueSession(email: string) {
  const { data, error } = await admin.auth.admin.generateLink({ type: "magiclink", email });
  if (error || !data?.properties?.hashed_token) throw new Error("Token sesi tidak dapat dibuat");
  return data.properties.hashed_token;
}

async function requireTeacher(req: Request) {
  const authorization = req.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const { data, error } = await admin.auth.getUser(match[1]);
  if (error || !data.user) return null;
  const { data: profile, error: profileError } = await admin.from("profiles")
    .select("id,role").eq("id", data.user.id).maybeSingle();
  if (profileError || profile?.role !== "teacher") return null;
  return data.user;
}

Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Metode tidak didukung." }, 405);
  try {
    const body = await req.json();
    const action = String(body.action || "");
    const email = normalizeEmail(body.email);
    const classCode = normalizeClassCode(body.class_code);
    if (!isValidEmail(email)) return json({ error: "Alamat email tidak valid." }, 400);
    if (!CLASS_CODES[classCode]) return json({ error: "Kode kelas tidak terdaftar." }, 400);

    if (action === "create_student") {
      const teacher = await requireTeacher(req);
      if (!teacher) return json({ error: "Akses hanya diberikan kepada akun guru." }, 403);
      const name = String(body.name || "").trim();
      if (!isValidStudentName(name)) return json({ error: "Nama siswa harus terdiri dari 2–100 karakter." }, 400);
      const recoveryCode = formatRecoveryCode(randomHex(24));
      const recoveryHash = await sha256(recoveryCode);
      const randomPassword = randomHex(32) + "aA!9";
      const className = CLASS_CODES[classCode];
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email, password: randomPassword, email_confirm: true,
        user_metadata: { display_name: name, class_code: className },
      });
      if (createError || !created.user) {
        return json({ error: "Akun tidak dapat dibuat. Periksa email atau hubungi administrator." }, 409);
      }
      const { error: insertError } = await admin.from("student_access_credentials").insert({
        user_id: created.user.id, email, class_code: classCode, recovery_hash: recoveryHash,
      });
      if (insertError) {
        const { error: cleanupError } = await admin.auth.admin.deleteUser(created.user.id);
        if (cleanupError) console.error("student cleanup failed:", cleanupError.message);
        return json({ error: "Pembuatan akun tidak dapat diselesaikan." }, 500);
      }
      return json({ recovery_code: recoveryCode });
    }

    if (action === "reset_student_code") {
      const teacher = await requireTeacher(req);
      if (!teacher) return json({ error: "Akses hanya diberikan kepada akun guru." }, 403);
      const { data: credential, error: lookupError } = await admin.from("student_access_credentials")
        .select("user_id,email,class_code")
        .eq("email", email).eq("class_code", classCode).maybeSingle();
      if (lookupError || !credential) return json({ error: "Akun siswa tidak ditemukan." }, 404);
      const recoveryCode = formatRecoveryCode(randomHex(24));
      const recoveryHash = await sha256(recoveryCode);
      const { error: updateError } = await admin.from("student_access_credentials")
        .update({ recovery_hash: recoveryHash }).eq("user_id", credential.user_id);
      if (updateError) return json({ error: "Kode pemulihan belum dapat diperbarui." }, 500);
      return json({ recovery_code: recoveryCode });
    }

    if (action === "login") {
      const recoveryCode = String(body.recovery_code || "").trim().toUpperCase();
      if (!isValidRecoveryCode(recoveryCode)) return json({ error: "Email atau kode pemulihan tidak cocok." }, 401);
      const { data: credential, error: lookupError } = await admin.from("student_access_credentials")
        .select("user_id,email,class_code,recovery_hash")
        .eq("email", email).eq("class_code", classCode).maybeSingle();
      if (lookupError || !credential) return json({ error: "Email atau kode pemulihan tidak cocok." }, 401);
      const submittedHash = await sha256(recoveryCode);
      if (!safeEqual(submittedHash, credential.recovery_hash)) {
        return json({ error: "Email atau kode pemulihan tidak cocok." }, 401);
      }
      const { data: authUser, error: userError } = await admin.auth.admin.getUserById(credential.user_id);
      if (userError || !authUser.user || authUser.user.email?.toLowerCase() !== email) {
        return json({ error: "Akun tidak dapat diverifikasi. Hubungi guru." }, 401);
      }
      return json({ token_hash: await issueSession(email) });
    }

    return json({ error: "Tindakan tidak dikenal." }, 400);
  } catch (error) {
    console.error("student-access error:", error instanceof Error ? error.message : "unknown");
    return json({ error: "Terjadi kesalahan pada server. Silakan coba kembali." }, 500);
  }
});
