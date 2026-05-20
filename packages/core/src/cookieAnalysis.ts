import { parseSetCookie } from "./cookie-analysis.js";
import type { CookieAnalysisInfo, CookieRecord } from "./types.js";

const normalizeSameSite = (value: string | null): CookieRecord["sameSite"] => {
  if (!value) return "missing";
  const normalized = value.toLowerCase();
  if (normalized === "strict") return "Strict";
  if (normalized === "lax") return "Lax";
  if (normalized === "none") return "None";
  return "missing";
};

export function analyzeCookieHeaders(setCookieHeaders: string[] | undefined): CookieAnalysisInfo | null {
  const parsedCookies = parseSetCookie(setCookieHeaders);
  if (!parsedCookies.length) {
    return null;
  }

  const cookies = parsedCookies.map((cookie) => {
    const hasHostPrefix = cookie.name.startsWith("__Host-");
    const hasSecurePrefix = cookie.name.startsWith("__Secure-");
    return {
      name: cookie.name,
      hasSecure: cookie.secure,
      hasHttpOnly: cookie.httpOnly,
      sameSite: normalizeSameSite(cookie.sameSite),
      hasHostPrefix,
      hasSecurePrefix,
      isSessionCookie: !cookie.expires && !cookie.maxAge,
      domain: cookie.domain,
      path: cookie.path,
    };
  });

  const publicCookies: CookieRecord[] = cookies.map(({ domain: _domain, path: _path, ...cookie }) => cookie);
  const cookiesWithoutSecure = publicCookies.filter((cookie) => !cookie.hasSecure).length;
  const cookiesWithoutHttpOnly = publicCookies.filter((cookie) => !cookie.hasHttpOnly).length;
  const cookiesWithSameSiteNone = publicCookies.filter((cookie) => cookie.sameSite === "None").length;
  const cookiesWithoutSameSite = publicCookies.filter((cookie) => cookie.sameSite === "missing").length;
  const issues: string[] = [];
  const strengths: string[] = [];

  if (cookiesWithoutSecure) {
    issues.push(`${cookiesWithoutSecure} cookie${cookiesWithoutSecure === 1 ? "" : "s"} missing Secure.`);
  }
  if (cookiesWithoutHttpOnly) {
    issues.push(`${cookiesWithoutHttpOnly} cookie${cookiesWithoutHttpOnly === 1 ? "" : "s"} missing HttpOnly.`);
  }
  if (cookiesWithSameSiteNone) {
    const noneWithoutSecure = publicCookies.filter((cookie) => cookie.sameSite === "None" && !cookie.hasSecure).length;
    issues.push(noneWithoutSecure
      ? `${noneWithoutSecure} SameSite=None cookie${noneWithoutSecure === 1 ? "" : "s"} missing Secure.`
      : `${cookiesWithSameSiteNone} cookie${cookiesWithSameSiteNone === 1 ? "" : "s"} allow cross-site use with SameSite=None.`);
  }
  if (cookiesWithoutSameSite) {
    issues.push(`${cookiesWithoutSameSite} cookie${cookiesWithoutSameSite === 1 ? "" : "s"} missing SameSite.`);
  }

  for (const cookie of cookies) {
    if (cookie.hasHostPrefix && (!cookie.hasSecure || cookie.domain || cookie.path !== "/")) {
      issues.push(`__Host- cookie ${cookie.name} does not meet Secure, Path=/, and no Domain requirements.`);
    }
    if (cookie.hasSecurePrefix && !cookie.hasSecure) {
      issues.push(`__Secure- cookie ${cookie.name} does not include Secure.`);
    }
  }

  if (!issues.length) {
    strengths.push("Cookies include the expected Secure, HttpOnly, and SameSite protections.");
  }
  if (publicCookies.some((cookie) => cookie.hasHostPrefix)) {
    strengths.push("__Host- cookie prefix is in use.");
  }
  if (publicCookies.some((cookie) => cookie.hasSecurePrefix)) {
    strengths.push("__Secure- cookie prefix is in use.");
  }

  return {
    cookies: publicCookies,
    cookiesWithoutSecure,
    cookiesWithoutHttpOnly,
    cookiesWithSameSiteNone,
    cookiesWithoutSameSite,
    issues,
    strengths,
  };
}
