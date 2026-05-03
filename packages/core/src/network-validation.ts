import dns from "node:dns/promises";
import net from "node:net";

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
  const normalized = value.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("fec0:") ||
    // IPv4-mapped addresses (e.g. ::ffff:127.0.0.1)
    normalized.startsWith("::ffff:") ||
    // 6to4 tunnels wrapping private IPv4 ranges
    normalized.startsWith("2002:7f") || // 127.x
    normalized.startsWith("2002:0a") || // 10.x
    normalized.startsWith("2002:c0a8")  // 192.168.x
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
  const ipVersion = net.isIP(value);
  if (ipVersion === 4) {
    return isPrivateIpv4(value);
  }
  if (ipVersion === 6) {
    return isPrivateIpv6(value);
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

  const lookups = await dns.lookup(targetUrl.hostname, { all: true });
  if (!lookups.length || lookups.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error(`Target ${targetUrl.hostname} did not resolve exclusively to public IP addresses.`);
  }
}

export async function assertPublicRedirectTarget(targetUrl: URL): Promise<void> {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Redirect target ${targetUrl.hostname} is not public and was blocked.`);
  }

  try {
    const lookups = await dns.lookup(targetUrl.hostname, { all: true });
    if (lookups.length && lookups.every((entry) => isPrivateAddress(entry.address))) {
      throw new Error(`Redirect target ${targetUrl.hostname} resolved only to private or loopback addresses and was blocked.`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("was blocked")) {
      // Explicitly blocked by our SSRF check — propagate.
      throw error;
    }
    // DNS resolution failures (NXDOMAIN, timeout) are logged but the redirect
    // is allowed to fail naturally at the HTTP layer rather than silently passing.
    // Re-throw so the caller can decide whether to abort the scan.
    throw error;
  }
}
