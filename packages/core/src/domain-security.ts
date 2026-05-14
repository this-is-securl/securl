import dns from "node:dns/promises";
import type { MxRecord, CaaRecord } from "node:dns";
import type { DomainSecurityInfo } from "./types.js";
import { DNS_LOOKUP_TIMEOUT_MS } from "./scannerConfig.js";
import { safeResolveWithTimeout } from "./utils.js";
import type { RequestTextFn } from "./network.js";

type SpfPolicyEvaluation = DomainSecurityInfo["emailPolicy"]["spf"];
type DmarcPolicyEvaluation = DomainSecurityInfo["emailPolicy"]["dmarc"];

async function fetchMtaStsPolicy(host: string, requestText: RequestTextFn) {
  const policyHost = `mta-sts.${host}`;
  const policyUrl = new URL(`https://${policyHost}/.well-known/mta-sts.txt`);

  try {
    const response = await requestText(policyUrl);
    if (response.statusCode >= 200 && response.statusCode < 300 && response.body.trim()) {
      return { policyUrl: policyUrl.toString(), policy: response.body.trim() };
    }
  } catch {
    // Ignore fetch failure and return a null policy below.
  }

  return { policyUrl: policyUrl.toString(), policy: null };
}

const parseDnsTags = (record: string): Map<string, string> => {
  const tags = new Map<string, string>();

  for (const part of record.split(";")) {
    const [key, ...valueParts] = part.trim().split("=");
    if (key && valueParts.length) {
      tags.set(key.toLowerCase(), valueParts.join("=").trim());
    }
  }

  return tags;
};

export const evaluateSpfPolicy = (spf: string | null): SpfPolicyEvaluation => {
  if (!spf) {
    return {
      status: "missing",
      allMechanism: null,
      dnsLookupMechanisms: 0,
      summary: "No SPF record was detected at the zone apex.",
    };
  }

  const mechanisms = spf.split(/\s+/).filter(Boolean);
  const allMechanism = mechanisms.find((mechanism) => /^[~?+-]?all$/i.test(mechanism))?.toLowerCase() || null;
  const normalizedAll = allMechanism === "all" ? "+all" : allMechanism;
  const dnsLookupMechanisms = mechanisms.filter((mechanism) => /^(?:[~?+-])?(?:include|a|mx|ptr|exists)(?::|$)/i.test(mechanism)).length;

  if (normalizedAll === "-all") {
    return {
      status: dnsLookupMechanisms > 10 ? "watch" : "strong",
      allMechanism: "-all",
      dnsLookupMechanisms,
      summary: dnsLookupMechanisms > 10
        ? "SPF uses hardfail, but appears to exceed the 10 DNS-lookup guidance limit."
        : "SPF uses hardfail, which is the strongest published all-mechanism.",
    };
  }

  if (normalizedAll === "~all") {
    return {
      status: "watch",
      allMechanism: "~all",
      dnsLookupMechanisms,
      summary: "SPF uses softfail; this is safer than no policy but weaker than hardfail.",
    };
  }

  if (normalizedAll === "?all" || normalizedAll === "+all") {
    return {
      status: "weak",
      allMechanism: normalizedAll,
      dnsLookupMechanisms,
      summary: "SPF ends with a neutral or permissive all-mechanism, so spoofing resistance is weak.",
    };
  }

  return {
    status: "watch",
    allMechanism: null,
    dnsLookupMechanisms,
    summary: "SPF is present, but no explicit all-mechanism was found.",
  };
};

const normalizeDmarcPolicy = (value: string | undefined): DmarcPolicyEvaluation["policy"] => {
  const normalized = value?.toLowerCase();
  return normalized === "reject" || normalized === "quarantine" || normalized === "none" ? normalized : null;
};

export const evaluateDmarcPolicy = (dmarc: string | null): DmarcPolicyEvaluation => {
  if (!dmarc) {
    return {
      status: "missing",
      policy: null,
      subdomainPolicy: null,
      pct: null,
      reporting: false,
      summary: "No DMARC record was detected.",
    };
  }

  const tags = parseDnsTags(dmarc);
  const policy = normalizeDmarcPolicy(tags.get("p"));
  const subdomainPolicy = normalizeDmarcPolicy(tags.get("sp"));
  const pctRaw = tags.get("pct");
  const pct = pctRaw && /^\d+$/.test(pctRaw) ? Math.max(0, Math.min(100, Number(pctRaw))) : null;
  const reporting = Boolean(tags.get("rua") || tags.get("ruf"));

  if (policy === "reject" || policy === "quarantine") {
    const reducedRollout = pct !== null && pct < 100;
    return {
      status: reducedRollout ? "watch" : "strong",
      policy,
      subdomainPolicy,
      pct,
      reporting,
      summary: reducedRollout
        ? `DMARC is enforcing ${policy}, but only for ${pct}% of mail.`
        : `DMARC is enforcing ${policy}.`,
    };
  }

  if (policy === "none") {
    return {
      status: "weak",
      policy,
      subdomainPolicy,
      pct,
      reporting,
      summary: "DMARC is present in monitoring mode only and does not enforce quarantine or reject.",
    };
  }

  return {
    status: "watch",
    policy,
    subdomainPolicy,
    pct,
    reporting,
    summary: "DMARC is present, but the policy tag could not be interpreted.",
  };
};

export async function analyzeDomainSecurity(host: string, requestText: RequestTextFn): Promise<DomainSecurityInfo> {
  const apexHost = host.startsWith("www.") ? host.slice(4) : host;
  const candidateHosts = [...new Set([host, apexHost])];
  const resolveDns = <T>(operation: () => Promise<T>) =>
    safeResolveWithTimeout(operation, DNS_LOOKUP_TIMEOUT_MS);

  const [
    mxByHost,
    nsByHost,
    txtRootByHost,
    txtDmarcByHost,
    caaByHost,
    txtMtaStsByHost,
    dsByHost,
  ] = await Promise.all([
    Promise.all(candidateHosts.map((candidate) => resolveDns(() => dns.resolveMx(candidate)))),
    Promise.all(candidateHosts.map((candidate) => resolveDns(() => dns.resolveNs(candidate)))),
    Promise.all(candidateHosts.map((candidate) => resolveDns(() => dns.resolveTxt(candidate)))),
    Promise.all(candidateHosts.map((candidate) => resolveDns(() => dns.resolveTxt(`_dmarc.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => resolveDns(() => dns.resolveCaa(candidate)))),
    Promise.all(candidateHosts.map((candidate) => resolveDns(() => dns.resolveTxt(`_mta-sts.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => resolveDns<unknown[]>(() => dns.resolve(candidate, "DS") as Promise<unknown[]>))),
  ]);

  const pickFirst = (values: (unknown[] | null)[]) => values.find((value) => value && value.length) || null;
  const mxRecordsRaw = pickFirst(mxByHost) || [];
  const nsRecordsRaw = pickFirst(nsByHost) || [];
  const txtRoot = pickFirst(txtRootByHost) || [];
  const txtDmarc = pickFirst(txtDmarcByHost) || [];
  const caaRaw = pickFirst(caaByHost) || [];
  const txtMtaSts = pickFirst(txtMtaStsByHost) || [];
  const dsRaw = pickFirst(dsByHost) || [];

  type DsRecord = { keyTag: number; algorithm: number; digestType: number; digest: string };
  const mxRecords = (mxRecordsRaw as MxRecord[])
    .sort((a, b) => a.priority - b.priority)
    .map((record) => `${record.priority} ${record.exchange}`);
  const nsRecords = (nsRecordsRaw as string[]) || [];
  const txtValues = (txtRoot as string[][]).map((entry) => entry.join(""));
  const dmarcValues = (txtDmarc as string[][]).map((entry) => entry.join(""));
  const mtaStsValues = (txtMtaSts as string[][]).map((entry) => entry.join(""));
  const caaRecords = (caaRaw as CaaRecord[]).flatMap((record) =>
    Object.entries(record)
      .filter(([key]) => key !== "critical")
      .map(([tag, value]) => `${tag} ${value}`),
  );
  const dsRecords = (dsRaw as DsRecord[]).map((record) => `${record.keyTag} ${record.algorithm} ${record.digestType} ${record.digest}`);
  const spf = txtValues.find((value) => value.toLowerCase().startsWith("v=spf1")) || null;
  const dmarc = dmarcValues.find((value) => value.toLowerCase().startsWith("v=dmarc1")) || null;
  const mtaStsDns = mtaStsValues.find((value) => value.toLowerCase().startsWith("v=stsv1")) || null;
  const mtaStsTargetHost = txtMtaStsByHost[0]?.length ? candidateHosts[0] : candidateHosts[1] || candidateHosts[0];
  const mtaStsPolicy = mtaStsDns ? await fetchMtaStsPolicy(mtaStsTargetHost, requestText) : { policyUrl: null, policy: null };
  const emailPolicy = {
    spf: evaluateSpfPolicy(spf),
    dmarc: evaluateDmarcPolicy(dmarc),
  };

  const issues: string[] = [];
  const strengths: string[] = [];

  if (!mxRecords.length) {
    issues.push("No MX records found.");
  } else {
    strengths.push("MX records are published.");
  }

  if (!spf) {
    issues.push("No SPF record detected at the zone apex.");
  } else if (emailPolicy.spf.status === "weak") {
    issues.push(emailPolicy.spf.summary);
  } else if (emailPolicy.spf.status === "watch") {
    issues.push(emailPolicy.spf.summary);
  } else {
    strengths.push(emailPolicy.spf.summary);
  }

  if (!dmarc) {
    issues.push("No DMARC record detected.");
  } else if (emailPolicy.dmarc.status === "weak") {
    issues.push(emailPolicy.dmarc.summary);
  } else if (emailPolicy.dmarc.status === "watch") {
    issues.push(emailPolicy.dmarc.summary);
  } else {
    strengths.push(emailPolicy.dmarc.summary);
  }

  if (!caaRecords.length) {
    issues.push("No CAA records found.");
  } else {
    strengths.push("CAA records restrict which certificate authorities may issue for the domain.");
  }

  if (!dsRecords.length) {
    issues.push("No DNSSEC DS records detected at the domain apex.");
  } else {
    strengths.push("DNSSEC DS records are published.");
  }

  if (!mtaStsDns) {
    issues.push("No MTA-STS DNS policy record detected.");
  } else if (!mtaStsPolicy.policy) {
    issues.push("MTA-STS DNS record exists, but the HTTPS policy file could not be fetched.");
  } else {
    strengths.push("MTA-STS is published.");
  }

  return {
    host: apexHost,
    mxRecords,
    nsRecords,
    caaRecords,
    dnssec: {
      enabled: dsRecords.length > 0,
      dsRecords,
      status: dsRecords.length > 0 ? "signed" : "not_signed",
    },
    spf,
    dmarc,
    emailPolicy,
    mtaSts: {
      dns: mtaStsDns,
      policyUrl: mtaStsPolicy.policyUrl,
      policy: mtaStsPolicy.policy,
    },
    issues,
    strengths,
  };
}
