import dns from "node:dns/promises";
import net from "node:net";
import { DNS_LOOKUP_TIMEOUT_MS } from "./scannerConfig.js";
import { withTimeout } from "./utils.js";

export function isPrivateIpv4(value: string): boolean {
  const [first, second] = value.split(".").map((part) => Number(part));
  if ([first, second].some((part) => Number.isNaN(part))) {
    return false;
  }

  return (
    first === 10 ||
    first === 127 ||
    first === 0 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19))
  );
}

export function isPrivateIpv6(value: string): boolean {
  const normalized = value.toLowerCase().replace(/^\[(.*)\]$/, "$1");
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("fec0:") ||
    normalized.startsWith("::ffff:") ||
    normalized.startsWith("2002:7f") ||
    normalized.startsWith("2002:0a") ||
    normalized.startsWith("2002:c0a8")
  );
}

export function isLocalHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal")
  );
}

export function isPrivateAddress(value: string): boolean {
  const normalized = value.replace(/^\[(.*)\]$/, "$1");
  const ipVersion = net.isIP(normalized);
  if (ipVersion === 4) {
    return isPrivateIpv4(normalized);
  }
  if (ipVersion === 6) {
    return isPrivateIpv6(normalized);
  }
  return false;
}

export async function assertPublicRequestTarget(targetUrl: URL): Promise<void> {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Target ${targetUrl.hostname} is not public and was blocked.`);
  }

  if (net.isIP(targetUrl.hostname)) {
    return;
  }

  const lookups = await withTimeout(
    dns.lookup(targetUrl.hostname, { all: true }),
    DNS_LOOKUP_TIMEOUT_MS,
    `DNS lookup for ${targetUrl.hostname} timed out.`,
  );
  if (!lookups.length || lookups.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error(`Target ${targetUrl.hostname} did not resolve exclusively to public IP addresses.`);
  }
}

export async function assertPublicRedirectTarget(targetUrl: URL): Promise<void> {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Redirect target ${targetUrl.hostname} is not public and was blocked.`);
  }

  try {
    const lookups = await withTimeout(
      dns.lookup(targetUrl.hostname, { all: true }),
      DNS_LOOKUP_TIMEOUT_MS,
      `DNS lookup for ${targetUrl.hostname} timed out.`,
    );
    if (!lookups.length || lookups.some((entry) => isPrivateAddress(entry.address))) {
      throw new Error(`Redirect target ${targetUrl.hostname} did not resolve exclusively to public IP addresses.`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("was blocked")) {
      throw error;
    }
    throw error;
  }
}
