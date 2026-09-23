export type AppRoute =
  | { kind: "home" }
  | { kind: "privacy" }
  | { kind: "report"; scanId: string }
  | { kind: "shared-link"; publicId: string }
  | { kind: "not-found" };

function trimTrailingSlashes(pathname: string): string {
  if (pathname === "/") return pathname;
  return pathname.replace(/\/+$/, "");
}

export function parseAppRoute(pathname: string): AppRoute {
  const normalizedPath = trimTrailingSlashes(pathname || "/");

  if (normalizedPath === "/") return { kind: "home" };
  if (normalizedPath === "/privacy") return { kind: "privacy" };

  const sharedLinkMatch = normalizedPath.match(/^\/shared\/link\/([A-Za-z0-9_-]{32})$/);
  if (sharedLinkMatch) {
    return { kind: "shared-link", publicId: sharedLinkMatch[1] };
  }

  const reportMatch = normalizedPath.match(/^\/report\/([^/]+)$/);
  if (!reportMatch) return { kind: "not-found" };

  try {
    const scanId = decodeURIComponent(reportMatch[1]);
    return scanId ? { kind: "report", scanId } : { kind: "not-found" };
  } catch {
    return { kind: "not-found" };
  }
}
