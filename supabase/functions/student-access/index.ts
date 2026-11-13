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
  if (error || !data?.properties?.hashed_token) throw new Error(error?.message || "Token sesi tidak dapat dibuat");
  return data.properties.hashed_token;
}

Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Metode tidak didukung." }, 405);
  try {
    const body = await req.json();
    const action = String(body.action || "");
    const email = normalizeEmail(body.email);
    const classCode = String(body.class_code || "").trim().toUpperCase().replace(/\s+/g, "");
    const className = CLASS_CODES[classCode];
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Alamat email tidak valid." }, 400);
    if (!className) return json({ error: "Kode kelas tidak terdaftar." }, 400);

    if (action === "register") {
      const name = String(body.name || "").trim();
      if (!isValidStudentName(name)) return json({ error: "Nama siswa harus terdiri dari 2–100 karakter." }, 400);
      const recoveryCode = formatRecoveryCode(randomHex(24));
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
        const { error: cleanupError } = await admin.auth.admin.deleteUser(created.user.id);
        if (cleanupError) console.error("registration cleanup failed:", cleanupError.message);
        return json({ error: "Pendaftaran tidak dapat diselesaikan. Silakan coba kembali." }, 500);
      }
      try {
        const tokenHash = await issueSession(email);
        return json({ token_hash: tokenHash, recovery_code: recoveryCode });
      } catch (sessionError) {
        const { error: cleanupError } = await admin.auth.admin.deleteUser(created.user.id);
        if (cleanupError) console.error("session cleanup failed:", cleanupError.message);
        console.error("registration session issuance failed:", sessionError instanceof Error ? sessionError.message : "unknown");
        return json({ error: "Sesi pendaftaran tidak dapat dibuat. Silakan ulangi pendaftaran." }, 500);
      }
    }

    if (action === "login") {
      const recoveryCode = String(body.recovery_code || "").trim().toUpperCase();
      if (!isValidRecoveryCode(recoveryCode)) return json({ error: "Format kode pemulihan tidak sesuai." }, 400);
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
        const { data: locked, error: attemptError } = await admin.rpc("record_student_access_failure", {
          p_user_id: credential.user_id,
        });
        if (attemptError) {
          console.error("failed-attempt update failed:", attemptError.message);
          return json({ error: "Percobaan masuk belum dapat diproses. Silakan coba kembali." }, 500);
        }
        if (locked) return json({ error: "Terlalu banyak percobaan. Coba kembali setelah 15 menit." }, 429);
        return json({ error: "Email, kode kelas, atau kode pemulihan tidak cocok." }, 401);
      }
      const { error: resetError } = await admin.from("student_access_credentials")
        .update({ failed_attempts: 0, locked_until: null }).eq("user_id", credential.user_id);
      if (resetError) {
        console.error("failed-attempt reset failed:", resetError.message);
        return json({ error: "Akun belum dapat diproses. Silakan coba kembali." }, 500);
      }
      return json({ token_hash: await issueSession(email) });
    }
    return json({ error: "Tindakan tidak dikenal." }, 400);
  } catch (error) {
    console.error("student-access error:", error instanceof Error ? error.message : "unknown");
    return json({ error: "Terjadi kesalahan pada server. Silakan coba kembali." }, 500);
  }
});
