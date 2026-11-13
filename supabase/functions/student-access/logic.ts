export const CLASS_CODES: Record<string, string> = { "VIIA2026": "VII A" };

export function normalizeEmail(value: unknown): string {
  return String(value || "").trim().toLowerCase();
}

export function normalizeClassCode(value: unknown): string {
  return String(value || "").trim().toUpperCase().replace(/\\s+/g, "");
}

export function isValidEmail(value: string): boolean {
  return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(value);
}

export function isValidStudentName(value: string): boolean {
  return value.length >= 2 && value.length <= 100;
}

export function isValidRecoveryCode(value: string): boolean {
  return /^[A-F0-9]{8}(-[A-F0-9]{8}){2}$/.test(value);
}

export function formatRecoveryCode(hex: string): string {
  if (!/^[A-F0-9]{48}$/.test(hex)) throw new Error("Recovery entropy must be 48 hexadecimal characters");
  return hex.match(/.{8}/g)!.join("-");
}

export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
