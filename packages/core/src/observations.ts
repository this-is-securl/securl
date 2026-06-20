import { createHash } from "node:crypto";
import type {
  AnalysisResult,
  ObservationCategory,
  ObservationLedger,
  ObservationStatus,
  ObservationValue,
  PostureObservation,
  ScanEvidenceKind,
  ScanEvidenceReference,
} from "./types.js";

type ObservationInput = Omit<PostureObservation, "id" | "observedAt" | "freshUntil"> & {
  ttlMs?: number;
};

const HOUR = 60 * 60 * 1000;
const categoryTtl: Record<ObservationCategory, number> = {
  transport: HOUR,
  header: HOUR,
  certificate: 6 * HOUR,
  dns: 24 * HOUR,
  email: 24 * HOUR,
  infrastructure: 24 * HOUR,
  technology: 24 * HOUR,
  trust: 24 * HOUR,
  availability: HOUR,
};

function kindToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 48) || "unknown";
}

function observationId(category: ObservationCategory, kind: string, subject: string, source: string): string {
  const fingerprint = createHash("sha256")
    .update(`${category}\u0000${kind}\u0000${subject.toLowerCase()}\u0000${source}`)
    .digest("hex")
    .slice(0, 20);
  return `obs_${fingerprint}`;
}

function evidence(
  kind: ScanEvidenceKind,
  label: string,
  observed: ObservationValue,
  source: ScanEvidenceReference["source"] = "observed",
): ScanEvidenceReference[] {
  return [{
    kind,
    label,
    observed: Array.isArray(observed) ? observed.join(", ") : observed === null ? null : String(observed),
    source,
  }];
}

export function buildObservationLedger(result: AnalysisResult): ObservationLedger {
  const generatedAt = result.scannedAt || new Date().toISOString();
  const observedAtMs = new Date(generatedAt).getTime();
  const baseMs = Number.isFinite(observedAtMs) ? observedAtMs : Date.now();
  const observations: PostureObservation[] = [];
  const add = (input: ObservationInput) => {
    observations.push({
      ...input,
      id: observationId(input.category, input.kind, input.subject, input.source),
      observedAt: generatedAt,
      freshUntil: new Date(baseMs + (input.ttlMs ?? categoryTtl[input.category])).toISOString(),
    });
  };

  add({
    category: "transport",
    kind: "http.status",
    subject: result.finalUrl,
    status: result.statusCode > 0 ? "observed" : "unavailable",
    value: result.statusCode > 0 ? result.statusCode : null,
    confidence: "high",
    source: "probe",
    evidence: evidence("probe", "HTTP response status", result.statusCode > 0 ? result.statusCode : null),
  });

  for (const header of result.headers) {
    add({
      category: "header",
      kind: `http.header.${header.key.toLowerCase()}`,
      subject: result.finalUrl,
      status: header.status === "missing" ? "missing" : "observed",
      value: header.value,
      confidence: "high",
      source: "header",
      evidence: evidence("header", header.label, header.value),
    });
  }

  const certificate = result.certificate;
  add({
    category: "certificate",
    kind: "tls.certificate.valid",
    subject: result.host,
    status: certificate.available ? "observed" : "unavailable",
    value: certificate.available ? certificate.valid && certificate.authorized : null,
    confidence: "high",
    source: "tls",
    evidence: evidence("tls", "Certificate validity", certificate.available ? certificate.valid && certificate.authorized : null),
  });
  add({
    category: "certificate",
    kind: "tls.certificate.days_remaining",
    subject: result.host,
    status: certificate.daysRemaining === null ? "unavailable" : "observed",
    value: certificate.daysRemaining,
    confidence: "high",
    source: "tls",
    evidence: evidence("tls", "Certificate days remaining", certificate.daysRemaining),
  });
  add({
    category: "transport",
    kind: "tls.protocol",
    subject: result.host,
    status: certificate.protocol ? "observed" : "unavailable",
    value: certificate.protocol,
    confidence: "high",
    source: "tls",
    evidence: evidence("tls", "Negotiated TLS protocol", certificate.protocol),
  });

  const domain = result.domainSecurity;
  add({
    category: "dns",
    kind: "dns.dnssec",
    subject: domain.host,
    status: domain.dnssec.status === "unknown" ? "unavailable" : domain.dnssec.enabled ? "observed" : "missing",
    value: domain.dnssec.status,
    confidence: domain.dnssec.status === "unknown" ? "low" : "high",
    source: "dns",
    evidence: evidence("dns", "DNSSEC status", domain.dnssec.status),
  });
  for (const [kind, policy] of [["email.spf", domain.emailPolicy.spf], ["email.dmarc", domain.emailPolicy.dmarc]] as const) {
    add({
      category: "email",
      kind,
      subject: domain.host,
      status: policy.status === "missing" ? "missing" : "observed",
      value: policy.status,
      confidence: "high",
      source: "dns",
      evidence: evidence("dns", kind === "email.spf" ? "SPF policy" : "DMARC policy", policy.status),
    });
  }

  add({
    category: "trust",
    kind: "public.security_txt",
    subject: result.host,
    status: result.securityTxt.status === "missing" ? "missing" : "observed",
    value: result.securityTxt.status,
    confidence: "high",
    source: "public_record",
    evidence: evidence("public_record", "security.txt status", result.securityTxt.status),
  });

  for (const provider of result.infrastructure.providers) {
    add({
      category: "infrastructure",
      kind: `infrastructure.provider.${provider.category}.${kindToken(provider.provider)}`,
      subject: result.host,
      status: provider.source === "technology" ? "inferred" : "observed",
      value: provider.provider,
      confidence: provider.confidence,
      source: "infrastructure",
      evidence: evidence(provider.source === "dns" || provider.source === "reverse_dns" ? "dns" : "header", provider.provider, provider.evidence, provider.source === "technology" ? "inferred" : "observed"),
    });
  }

  for (const technology of result.technologies) {
    add({
      category: "technology",
      kind: `technology.${technology.category}.${kindToken(technology.name)}`,
      subject: result.host,
      status: technology.detection === "inferred" ? "inferred" : "observed",
      value: technology.version ? `${technology.name}@${technology.version}` : technology.name,
      confidence: technology.confidence,
      source: "technology",
      evidence: evidence("html", technology.name, technology.evidence, technology.detection),
    });
  }

  for (const provider of result.wafFingerprint.providers) {
    add({
      category: "infrastructure",
      kind: `infrastructure.waf.${kindToken(provider.name)}`,
      subject: result.host,
      status: provider.detection === "inferred" ? "inferred" : "observed",
      value: provider.name,
      confidence: provider.confidence,
      source: "infrastructure",
      evidence: evidence("header", `${provider.name} WAF`, provider.evidence, provider.detection),
    });
  }

  if (result.assessmentLimitation.limited) {
    add({
      category: "availability",
      kind: "assessment.limitation",
      subject: result.finalUrl,
      status: "unavailable",
      value: result.assessmentLimitation.kind,
      confidence: "high",
      source: "availability",
      evidence: evidence("score_driver", "Assessment limitation", result.assessmentLimitation.detail),
    });
  }

  observations.sort((left, right) => left.id.localeCompare(right.id));
  const byStatus: Record<ObservationStatus, number> = {
    observed: 0,
    inferred: 0,
    missing: 0,
    unavailable: 0,
  };
  const byCategory: Partial<Record<ObservationCategory, number>> = {};
  for (const observation of observations) {
    byStatus[observation.status] += 1;
    byCategory[observation.category] = (byCategory[observation.category] ?? 0) + 1;
  }

  return {
    version: "1.0",
    target: result.finalUrl,
    generatedAt,
    observations,
    summary: {
      total: observations.length,
      byStatus,
      byCategory,
      highConfidence: observations.filter((observation) => observation.confidence === "high").length,
    },
  };
}
