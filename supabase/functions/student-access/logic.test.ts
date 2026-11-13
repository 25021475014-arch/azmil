import {
  CLASS_CODES, formatRecoveryCode, isValidEmail, isValidRecoveryCode,
  isValidStudentName, normalizeClassCode, normalizeEmail, safeEqual,
} from "./logic.ts";

Deno.test("rollout accepts VII A only", () => {
  if (CLASS_CODES.VIIA2026 !== "VII A") throw new Error("VII A code missing");
  if ("VIIB2026" in CLASS_CODES) throw new Error("VII B must remain disabled");
  if (normalizeClassCode(" viia 2026 ") !== "VIIA2026") throw new Error("class normalization failed");
  if (CLASS_CODES[normalizeClassCode("VII B 2026")]) throw new Error("unexpected class accepted");
});

Deno.test("email normalization and validation", () => {
  const email = normalizeEmail("  Student.Example@MAIL.COM  ");
  if (email !== "student.example@mail.com") throw new Error("email normalization failed");
  if (!isValidEmail(email)) throw new Error("valid email rejected");
  for (const invalid of ["", "student", "a@", "@mail.com", "a b@mail.com"]) {
    if (isValidEmail(invalid)) throw new Error(`invalid email accepted: ${invalid}`);
  }
});

Deno.test("student name boundaries", () => {
  if (!isValidStudentName("AB")) throw new Error("minimum valid name rejected");
  if (!isValidStudentName("A".repeat(100))) throw new Error("maximum valid name rejected");
  if (isValidStudentName("A")) throw new Error("one-character name accepted");
  if (isValidStudentName("A".repeat(101))) throw new Error("overlong name accepted");
});

Deno.test("recovery code format and normalization", () => {
  const code = formatRecoveryCode("A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0");
  if (code !== "A1B2C3D4-E5F60718-293A4B5C-6D7E8F90-12345678-9ABCDEF0") {
    throw new Error("recovery code grouping failed");
  }
  if (!isValidRecoveryCode(code)) throw new Error("generated code rejected");
  if (!isValidRecoveryCode(code.toLowerCase().toUpperCase())) throw new Error("uppercase code rejected");
  for (const invalid of ["", "ABC", "A".repeat(48), "GGGGGGGG-EEEEEEEE-FFFFFFFF"]) {
    if (isValidRecoveryCode(invalid)) throw new Error(`invalid recovery code accepted: ${invalid}`);
  }
});

Deno.test("constant-time comparison returns correct equality result", () => {
  if (!safeEqual("abcdef012345", "abcdef012345")) throw new Error("equal strings differ");
  if (safeEqual("abcdef012345", "abcdef012346")) throw new Error("different strings match");
  if (safeEqual("short", "longer")) throw new Error("different lengths match");
});
