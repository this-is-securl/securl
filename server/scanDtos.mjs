function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

export function buildScanSummaryPayload(scan) {
  return {
    summary: scan.summary,
  };
}

export function buildScanFindingsPayload(scan) {
  const result = scan.result;
  if (!result) {
    return {
      findings: [],
      strengths: [],
      priorityActions: [],
    };
  }

  return {
    findings: normalizeArray(result.issues),
    strengths: normalizeArray(result.strengths),
    priorityActions: normalizeArray(result.executiveSummary?.takeaways),
  };
}

export function buildScanEvidencePayload(scan) {
  const result = scan.result;
  if (!result) {
    return {
      evidence: null,
    };
  }

  return {
    evidence: {
      headers: normalizeArray(result.headers),
      rawHeaders: result.rawHeaders ?? {},
      cookies: normalizeArray(result.cookies),
      redirects: normalizeArray(result.redirects),
      certificate: result.certificate ?? null,
      exposure: result.exposure ?? null,
      apiSurface: result.apiSurface ?? null,
      corsSecurity: result.corsSecurity ?? null,
      htmlSecurity: result.htmlSecurity ?? null,
      domainSecurity: result.domainSecurity ?? null,
      securityTxt: result.securityTxt ?? null,
      publicSignals: result.publicSignals ?? null,
      infrastructure: result.infrastructure ?? null,
      identityProvider: result.identityProvider ?? null,
      thirdPartyTrust: result.thirdPartyTrust ?? null,
      aiSurface: result.aiSurface ?? null,
      technologies: normalizeArray(result.technologies),
      ctDiscovery: result.ctDiscovery ?? null,
      wafFingerprint: result.wafFingerprint ?? null,
      crawl: result.crawl ?? null,
    },
  };
}

export function buildScanHistoryPayload(scan, events) {
  return {
    scan: {
      id: scan.id,
      status: scan.status,
      requestedAt: scan.requestedAt,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
    },
    events: normalizeArray(events),
  };
}

export function buildTargetHistoryPayload(url, scans) {
  return {
    target: {
      url,
    },
    scans: normalizeArray(scans),
  };
}
