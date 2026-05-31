import dns from "node:dns/promises";
import net from "node:net";
import { DNS_LOOKUP_TIMEOUT_MS } from "./scannerConfig.js";
import { withTimeout } from "./utils.js";

export interface ValidatedAddress {
  address: string;
  family: number;
}

interface PinnedLookupOptions {
  family?: number | "IPv4" | "IPv6";
  all?: boolean;
}

type PinnedLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | ValidatedAddress[],
  family?: number,
) => void;

/** Node's lookup callback used by http/https request `lookup` option. */
export type PinnedLookup = (
  hostname: string,
  options: PinnedLookupOptions | PinnedLookupCallback,
  callback?: PinnedLookupCallback,
) => void;

function stripBrackets(value: string): string {
  return value.replace(/^\[(.*)\]$/, "$1");
}

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

// Decode the IPv4 address embedded in IPv4-mapped (::ffff:a.b.c.d / ::ffff:HHHH:HHHH),
// 6to4 (2002:HHHH:HHHH::) and NAT64 (64:ff9b::a.b.c.d) IPv6 forms.
function extractEmbeddedIpv4(normalized: string): string | null {
  // Dotted-quad already present in the address (e.g. ::ffff:127.0.0.1, 64:ff9b::127.0.0.1).
  const dotted = normalized.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) {
    return dotted[1];
  }

  const hexPairToIpv4 = (high: string, low: string): string | null => {
    const h = Number.parseInt(high, 16);
    const l = Number.parseInt(low, 16);
    if (Number.isNaN(h) || Number.isNaN(l)) {
      return null;
    }
    return `${(h >> 8) & 0xff}.${h & 0xff}.${(l >> 8) & 0xff}.${l & 0xff}`;
  };

  // IPv4-mapped in hextet form: ::ffff:7f00:1
  const mapped = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    return hexPairToIpv4(mapped[1], mapped[2]);
  }

  // 6to4: 2002:HHHH:HHHH::/16 carries the IPv4 gateway in the next 32 bits.
  const sixToFour = normalized.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})/);
  if (sixToFour) {
    return hexPairToIpv4(sixToFour[1], sixToFour[2]);
  }

  return null;
}

export function isPrivateIpv6(value: string): boolean {
  const normalized = stripBrackets(value.toLowerCase());

  if (normalized === "::1" || normalized === "::") {
    return true;
  }

  // Unique local (fc00::/7) and link-local (fe80::/10, i.e. fe80–febf).
  const firstHextet = Number.parseInt(normalized.split(":")[0] || "", 16);
  if (!Number.isNaN(firstHextet)) {
    if ((firstHextet & 0xfe00) === 0xfc00) {
      return true; // fc00::/7
    }
    if ((firstHextet & 0xffc0) === 0xfe80) {
      return true; // fe80::/10
    }
    if (firstHextet === 0xfec0) {
      return true; // deprecated site-local
    }
  }

  // IPv4-mapped (::ffff:*) is never a routable IPv6 destination; block and, when
  // possible, also classify the embedded IPv4 so the message is accurate.
  if (normalized.startsWith("::ffff:")) {
    return true;
  }

  // 6to4 and NAT64 tunnels can smuggle a private IPv4 destination.
  if (normalized.startsWith("2002:") || normalized.startsWith("64:ff9b:")) {
    const embedded = extractEmbeddedIpv4(normalized);
    if (embedded && isPrivateIpv4(embedded)) {
      return true;
    }
  }

  return false;
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
  const normalized = stripBrackets(value);
  const ipVersion = net.isIP(normalized);
  if (ipVersion === 4) {
    return isPrivateIpv4(normalized);
  }
  if (ipVersion === 6) {
    return isPrivateIpv6(normalized);
  }
  return false;
}

async function resolveValidatedAddresses(
  hostname: string,
  blockedMessage: string,
  unresolvedMessage: string,
): Promise<ValidatedAddress[]> {
  const literal = stripBrackets(hostname);
  const literalVersion = net.isIP(literal);
  if (literalVersion !== 0) {
    if (isPrivateAddress(literal)) {
      throw new Error(blockedMessage);
    }
    return [{ address: literal, family: literalVersion }];
  }

  const lookups = await withTimeout(
    dns.lookup(hostname, { all: true }),
    DNS_LOOKUP_TIMEOUT_MS,
    `DNS lookup for ${hostname} timed out.`,
  );
  if (!lookups.length || lookups.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error(unresolvedMessage);
  }
  return lookups.map((entry) => ({ address: entry.address, family: entry.family }));
}

/**
 * Validate that `targetUrl` is a public destination and return the exact set of
 * IP addresses it resolved to. Callers MUST connect using {@link createPinnedLookup}
 * with the returned addresses so the socket cannot be re-pointed at a private IP
 * between validation and connection (DNS-rebinding / TOCTOU SSRF).
 */
export async function assertPublicRequestTarget(targetUrl: URL): Promise<ValidatedAddress[]> {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Target ${targetUrl.hostname} is not public and was blocked.`);
  }

  return resolveValidatedAddresses(
    targetUrl.hostname,
    `Target ${targetUrl.hostname} is not public and was blocked.`,
    `Target ${targetUrl.hostname} did not resolve exclusively to public IP addresses.`,
  );
}

export async function assertPublicRedirectTarget(targetUrl: URL): Promise<ValidatedAddress[]> {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Redirect target ${targetUrl.hostname} is not public and was blocked.`);
  }

  return resolveValidatedAddresses(
    targetUrl.hostname,
    `Redirect target ${targetUrl.hostname} is not public and was blocked.`,
    `Redirect target ${targetUrl.hostname} did not resolve exclusively to public IP addresses.`,
  );
}

/**
 * Build a `lookup` function for http/https requests that only ever yields the
 * pre-validated public addresses, closing the gap between validation and the
 * connection's own DNS resolution.
 */
export function createPinnedLookup(addresses: ValidatedAddress[]): PinnedLookup {
  return function pinnedLookup(_hostname, options, callback) {
    const cb = (typeof options === "function" ? options : callback) as PinnedLookupCallback;
    const opts: PinnedLookupOptions = typeof options === "function" ? {} : options || {};

    if (!addresses.length) {
      cb(new Error("No validated address available for pinned lookup.") as NodeJS.ErrnoException, "", 0);
      return;
    }

    const requestedFamily = opts.family === 4 || opts.family === "IPv4"
      ? 4
      : opts.family === 6 || opts.family === "IPv6"
        ? 6
        : 0;
    const matching = requestedFamily
      ? addresses.filter((entry) => entry.family === requestedFamily)
      : addresses;
    const selected = matching.length ? matching : addresses;

    if (opts.all) {
      cb(null, selected.map((entry) => ({ address: entry.address, family: entry.family })));
      return;
    }

    cb(null, selected[0].address, selected[0].family);
  };
}
