import fs from "node:fs";
import path from "node:path";

function getMimeType(filePath) {
  const ext = path.extname(filePath);
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}

function resolveStaticPath(baseDir, requestPath) {
  const trimmed = requestPath.replace(/^\/+/, "");
  const decoded = (() => {
    try {
      return decodeURIComponent(trimmed);
    } catch {
      return trimmed;
    }
  })();
  const normalizedRequest = path.normalize(decoded || "index.html");
  if (normalizedRequest.startsWith("..") || path.isAbsolute(normalizedRequest)) {
    return null;
  }

  const resolved = path.resolve(baseDir, normalizedRequest);
  const baseWithSep = baseDir.endsWith(path.sep) ? baseDir : `${baseDir}${path.sep}`;
  if (resolved !== baseDir && !resolved.startsWith(baseWithSep)) {
    return null;
  }

  return resolved;
}

export function createStaticHandler({
  distDir,
  publicDir,
  isProduction,
  telemetry,
}) {
  const resolvedPathCache = new Map();

  return function serveStatic(requestPath, method, response) {
    const cleanPath = requestPath === "/" ? "/index.html" : requestPath;
    const staticTarget = resolveStaticPath(distDir, cleanPath);
    const publicTarget = resolveStaticPath(publicDir, cleanPath);
    const fallbackTarget = path.join(distDir, "index.html");

    if (!staticTarget || !publicTarget) {
      response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Invalid request path.");
      return;
    }

    let preferredPath = resolvedPathCache.get(cleanPath);
    if (preferredPath === undefined) {
      preferredPath = fs.existsSync(staticTarget)
        ? staticTarget
        : fs.existsSync(publicTarget)
          ? publicTarget
          : fs.existsSync(fallbackTarget)
            ? fallbackTarget
            : null;
      resolvedPathCache.set(cleanPath, preferredPath);
    }

    if (!preferredPath) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Frontend build not found. Run `npm run build` for a production preview.");
      return;
    }

    if (method === "GET" && path.basename(preferredPath) === "index.html") {
      telemetry.recordPageLoad();
    }

    const connectSources = ["'self'"];
    if (!isProduction) {
      connectSources.push("http://127.0.0.1:8787", "http://localhost:8787");
    }

    response.writeHead(200, {
      "Content-Type": getMimeType(preferredPath),
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Content-Security-Policy": `default-src 'self'; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; connect-src ${connectSources.join(" ")};`,
    });
    if (method === "HEAD") {
      response.end();
      return;
    }
    const stream = fs.createReadStream(preferredPath);
    stream.on("error", (_err) => {
      if (!response.headersSent) {
        response.writeHead(500, { "Content-Type": "text/plain" });
      }
      response.end();
    });
    stream.pipe(response);
  };
}
