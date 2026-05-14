import http from "node:http";
import https from "node:https";
import { OBSERVATIONAL_TLS_OPTIONS } from "./certificate.js";
import { REDIRECT_LIMIT, REQUEST_TIMEOUT_MS, TEXT_BODY_LIMIT } from "./scannerConfig.js";
import { headerValue } from "./utils.js";
import { assertPublicRedirectTarget, assertPublicRequestTarget } from "./network-validation.js";

export const SCANNER_USER_AGENT = "ExternalPostureInsight/1.0";

export interface RequestHeadResult {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  elapsedMs: number;
}

export interface RequestTextResult {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface RequestJsonResult<T = unknown> {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: T | null;
}

export type RequestTextFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<RequestTextResult>;
export type RequestJsonFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<RequestJsonResult>;

interface RequestOptions {
  timeoutMs?: number;
}

export function requestOnce(targetUrl: URL, method = "HEAD", options: RequestOptions = {}): Promise<RequestHeadResult> {
  return requestWithHeaders(targetUrl, method, {}, options);
}

export async function requestWithHeaders(
  targetUrl: URL,
  method = "HEAD",
  extraHeaders: Record<string, string> = {},
  options: RequestOptions = {},
): Promise<RequestHeadResult> {
  await assertPublicRequestTarget(targetUrl);
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;
  const startedAt = Date.now();
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const request = transport.request(
      targetUrl,
      {
        method,
        ...OBSERVATIONAL_TLS_OPTIONS,
        headers: {
          "User-Agent": SCANNER_USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Encoding": "identity",
          ...extraHeaders,
        },
      },
      (response) => {
        response.resume();
        resolve({
          statusCode: response.statusCode || 0,
          headers: response.headers,
          elapsedMs: Date.now() - startedAt,
        });
      },
    );

    request.on("error", reject);
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error("Request timed out."));
    });
    request.end();
  });
}

export async function requestText(
  targetUrl: URL,
  extraHeaders: Record<string, string> = {},
  options: RequestOptions = {},
): Promise<RequestTextResult> {
  await assertPublicRequestTarget(targetUrl);
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const request = transport.request(
      targetUrl,
      {
        method: "GET",
        ...OBSERVATIONAL_TLS_OPTIONS,
        headers: {
          "User-Agent": SCANNER_USER_AGENT,
          Accept: "text/plain,text/*;q=0.9,*/*;q=0.1",
          "Accept-Encoding": "identity",
          ...extraHeaders,
        },
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > TEXT_BODY_LIMIT) {
            body = body.slice(0, TEXT_BODY_LIMIT);
          }
        });
        response.on("end", () => {
          resolve({
            statusCode: response.statusCode || 0,
            headers: response.headers,
            body,
          });
        });
      },
    );

    request.on("error", reject);
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error("Request timed out."));
    });
    request.end();
  });
}

export async function requestJson(
  targetUrl: URL,
  extraHeaders: Record<string, string> = {},
  options: RequestOptions = {},
): Promise<RequestJsonResult> {
  const response = await requestText(targetUrl, {
    Accept: "application/json,text/plain;q=0.9,*/*;q=0.1",
    ...extraHeaders,
  }, options);
  return {
    ...response,
    json: response.body ? JSON.parse(response.body) : null,
  };
}

export async function fetchWithRedirects(initialUrl: URL, redirectLimit = REDIRECT_LIMIT, options: RequestOptions = {}) {
  const redirects: Array<{ url: string; statusCode: number; location: string | null; secure: boolean }> = [];
  let currentUrl = initialUrl;
  let response = await requestOnce(currentUrl, "HEAD", options);

  if (response.statusCode === 405 || response.statusCode === 403) {
    response = await requestOnce(currentUrl, "GET", options);
  }

  while (
    [301, 302, 303, 307, 308].includes(response.statusCode) &&
    headerValue(response.headers, "location") &&
    redirects.length < redirectLimit
  ) {
    const location = headerValue(response.headers, "location");
    redirects.push({
      url: currentUrl.toString(),
      statusCode: response.statusCode,
      location,
      secure: currentUrl.protocol === "https:",
    });
    currentUrl = new URL(location!, currentUrl);
    await assertPublicRedirectTarget(currentUrl);
    response = await requestOnce(currentUrl, "HEAD", options);
    if (response.statusCode === 405 || response.statusCode === 403) {
      response = await requestOnce(currentUrl, "GET", options);
    }
  }

  redirects.push({
    url: currentUrl.toString(),
    statusCode: response.statusCode,
    location: null,
    secure: currentUrl.protocol === "https:",
  });

  return { finalUrl: currentUrl, redirects, response };
}
