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

/**
 * Historical public API name. Returns true for every IPv4 destination that is
 * unsuitable for public outbound requests, including private and other IANA
 * non-global special-purpose ranges.
 */
export function isPrivateIpv4(value: string): boolean {
  const octets = value.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const address = octets.reduce((result, octet) => (result << 8n) | BigInt(octet), 0n);
  const inCidr = (base: string, prefix: number): boolean => {
    const baseValue = base.split(".").reduce((result, octet) => (result << 8n) | BigInt(octet), 0n);
    const shift = BigInt(32 - prefix);
    return (address >> shift) === (baseValue >> shift);
  };

  // IANA IPv4 special-purpose ranges that are not globally routable unicast.
  // Two anycast services inside 192.0.0.0/24 are explicitly globally reachable.
  if (value === "192.0.0.9" || value === "192.0.0.10") {
    return false;
  }
  return [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ].some(([base, prefix]) => inCidr(base as string, prefix as number));
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

/** IPv6 counterpart to {@link isPrivateIpv4}; includes non-unicast special use. */
export function isPrivateIpv6(value: string): boolean {
  const normalized = stripBrackets(value.toLowerCase());
  const parse = (input: string): bigint | null => {
    let expanded = input;
    const embedded = extractEmbeddedIpv4(input);
    if (/\d+\.\d+\.\d+\.\d+$/.test(input) && embedded) {
      const parts = embedded.split(".").map(Number);
      expanded = input.replace(/\d+\.\d+\.\d+\.\d+$/, `${((parts[0] << 8) | parts[1]).toString(16)}:${((parts[2] << 8) | parts[3]).toString(16)}`);
    }
    const halves = expanded.split("::");
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
    const words = [...left, ...Array(missing).fill("0"), ...right];
    if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
    return words.reduce((result, word) => (result << 16n) | BigInt(`0x${word}`), 0n);
  };
  const address = parse(normalized);
  if (address === null) return false;
  const inCidr = (base: string, prefix: number): boolean => {
    const baseValue = parse(base);
    if (baseValue === null) return false;
    const shift = BigInt(128 - prefix);
    return (address >> shift) === (baseValue >> shift);
  };

  // Preserve globally routable 6to4 destinations, but apply the complete IPv4
  // boundary to the gateway embedded in the 2002::/16 address.
  if (normalized.startsWith("2002:") || normalized.startsWith("64:ff9b:")) {
    const embedded = extractEmbeddedIpv4(normalized);
    return embedded ? isPrivateIpv4(embedded) : true;
  }

  // IANA IPv6 special-purpose space that is not globally routable unicast.
  return [
    ["::", 128],
    ["::1", 128],
    ["::ffff:0:0", 96],
    ["64:ff9b:1::", 48],
    ["100::", 64],
    ["2001::", 32], // Teredo
    ["2001:2::", 48], // benchmarking
    ["2001:10::", 28], // deprecated ORCHID
    ["2001:20::", 28], // ORCHIDv2 identifiers, not routed locators
    ["2001:db8::", 32], // documentation
    ["3fff::", 20], // documentation
    ["fc00::", 7],
    ["fe80::", 10],
    ["fec0::", 10], // deprecated site-local
    ["ff00::", 8],
  ].some(([base, prefix]) => inCidr(base as string, prefix as number));
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
