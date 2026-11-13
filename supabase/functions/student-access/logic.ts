export const CLASS_CODES: Record<string, string> = { "VIIA2026": "VII A" };

export function normalizeEmail(value: unknown): string {
  return String(value || "").trim().toLowerCase();
}
export function normalizeClassCode(value: unknown): string {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}
export function normalizeStudentName(value: unknown): string {
  return String(value || "").trim().replace(/\s+/g, " ").toLocaleLowerCase("id-ID");
}
export function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
export function isValidStudentName(value: string): boolean {
  return value.trim().length >= 2 && value.trim().length <= 100;
}
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
