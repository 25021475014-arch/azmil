import { createClient } from "npm:@supabase/supabase-js@2";
import {
  CLASS_CODES, isValidEmail, isValidStudentName, normalizeClassCode,
  normalizeEmail, normalizeStudentName, safeEqual,
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
  return [...data].map(v => v.toString(16).padStart(2, "0")).join("");
}

const url = Deno.env.get("SUPABASE_URL")!;
const secretKeys = Deno.env.get("SUPABASE_SECRET_KEYS");
const secretKey = secretKeys ? JSON.parse(secretKeys).default : Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const classPassword = Deno.env.get("CLASS_PASSWORD_VIIA");
if (!url || !secretKey) throw new Error("Supabase server credentials are not configured");
const admin = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false } });

async function issueSession(email: string) {
  const { data, error } = await admin.auth.admin.generateLink({ type: "magiclink", email });
  if (error || !data?.properties?.hashed_token) throw new Error("Token sesi tidak dapat dibuat");
  return data.properties.hashed_token;
}

async function findAuthUser(email: string) {
  const { data, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (error) throw error;
  return data.users.find(user => user.email?.toLowerCase() === email) || null;
}

async function getStudentProfile(userId: string) {
  const { data, error } = await admin.from("profiles")
    .select("id,display_name,class_code,role").eq("id", userId).maybeSingle();
  if (error) throw error;
  return data;
}

Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Metode tidak didukung." }, 405);

  try {
    const body = await req.json();
    if (String(body.action || "") !== "login") {
      return json({ error: "Tindakan tidak dikenal." }, 400);
    }
    const email = normalizeEmail(body.email);
    const name = String(body.name || "").trim().replace(/\s+/g, " ");
    const classCode = normalizeClassCode(body.class_code);
    const submittedPassword = String(body.class_password || "");

    if (!isValidEmail(email)) return json({ error: "Alamat email tidak valid." }, 400);
    if (!isValidStudentName(name)) return json({ error: "Nama lengkap harus terdiri dari 2–100 karakter." }, 400);
    if (!CLASS_CODES[classCode]) return json({ error: "Kelas tidak terdaftar." }, 400);
    if (!classPassword) {
      console.error("CLASS_PASSWORD_VIIA secret is not configured");
      return json({ error: "Login siswa belum dikonfigurasi. Hubungi guru." }, 503);
    }
    if (!safeEqual(submittedPassword, classPassword)) {
      return json({ error: "Email, nama, atau kata sandi kelas tidak sesuai." }, 401);
    }

    let authUser = await findAuthUser(email);
    if (!authUser) {
      const randomPassword = randomHex(32) + "aA!9";
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email, password: randomPassword, email_confirm: true,
        user_metadata: { display_name: name, class_code: CLASS_CODES[classCode] },
      });
      if (createError || !created.user) {
        authUser = await findAuthUser(email);
        if (!authUser) {
          console.error("student account provisioning failed:", createError?.message || "unknown");
          return json({ error: "Akun siswa belum dapat dibuat. Periksa email atau hubungi guru." }, 409);
        }
      } else {
        authUser = created.user;
      }
    }

    const profile = await getStudentProfile(authUser.id);
    if (!profile || profile.role !== "student" || profile.class_code !== CLASS_CODES[classCode]) {
      return json({ error: "Email ini tidak terdaftar sebagai akun siswa kelas VII A." }, 403);
    }
    if (normalizeStudentName(profile.display_name) !== normalizeStudentName(name)) {
      return json({ error: "Nama tidak sesuai dengan nama yang tersimpan untuk email tersebut." }, 401);
    }
    return json({ token_hash: await issueSession(email) });
  } catch (error) {
    console.error("student-access error:", error instanceof Error ? error.message : "unknown");
    return json({ error: "Terjadi kesalahan pada server. Silakan coba kembali." }, 500);
  }
});
