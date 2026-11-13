import {
  CLASS_CODES, isValidEmail, isValidStudentName, normalizeClassCode,
  normalizeEmail, normalizeStudentName, safeEqual,
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

Deno.test("student name validation and normalization", () => {
  if (!isValidStudentName("AB")) throw new Error("minimum valid name rejected");
  if (!isValidStudentName("A".repeat(100))) throw new Error("maximum valid name rejected");
  if (isValidStudentName("A")) throw new Error("one-character name accepted");
  if (isValidStudentName("A".repeat(101))) throw new Error("overlong name accepted");
  if (normalizeStudentName("  Siswa   Kelas VII A ") !== "siswa kelas vii a") {
    throw new Error("name normalization failed");
  }
});

Deno.test("password comparison is exact and case-sensitive", () => {
  if (!safeEqual("Kelas123", "Kelas123")) throw new Error("equal strings differ");
  if (safeEqual("Kelas123", "kelas123")) throw new Error("case-sensitive comparison failed");
  if (safeEqual("short", "longer")) throw new Error("different lengths match");
});
