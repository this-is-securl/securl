import crypto from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(crypto.scrypt);
const DEFAULT_SESSION_TTL_DAYS = 30;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 256;

const normalizeEmail = (value) => String(value || "").trim().toLowerCase();
const normalizeDisplayName = (value) => {
  const normalized = String(value || "").trim();
  return normalized ? normalized.slice(0, 120) : null;
};

const buildPublicUser = (user) => ({
  id: user.id,
  email: user.email,
  displayName: user.displayName ?? null,
  createdAt: user.createdAt,
});

const getPresentedBearerToken = (request) => {
  const candidate = request.headers.authorization;
  const raw = Array.isArray(candidate) ? candidate[0] || "" : typeof candidate === "string" ? candidate : "";
  const trimmed = raw.trim();
  const separatorIndex = trimmed.indexOf(" ");
  if (separatorIndex < 0) {
    return "";
  }
  const scheme = trimmed.slice(0, separatorIndex);
  const token = trimmed.slice(separatorIndex + 1).trim();
  if (scheme.toLowerCase() !== "bearer" || !token) {
    return "";
  }
  return token;
};

async function fingerprintToken(token, salt) {
  const digest = await scryptAsync(token, salt, 32);
  return `${salt}:${digest.toString("hex")}`;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = await scryptAsync(password, salt, 64);
  return `scrypt$${salt}$${digest.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  const [scheme, salt, digest] = String(storedHash || "").split("$");
  if (scheme !== "scrypt" || !salt || !digest) {
    return false;
  }
  const derived = await scryptAsync(password, salt, 64);
  const stored = Buffer.from(digest, "hex");
  return stored.length === derived.length && crypto.timingSafeEqual(stored, derived);
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getSessionTtlDays() {
  const raw = Number(process.env.AUTH_SESSION_TTL_DAYS || DEFAULT_SESSION_TTL_DAYS);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_SESSION_TTL_DAYS;
  }
  return Math.floor(raw);
}

function buildSessionEnvelope(session, token = null) {
  return {
    ...(token ? { token } : {}),
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    lastSeenAt: session.lastSeenAt,
  };
}

function validateCredentials({ email, password }) {
  const normalizedEmail = normalizeEmail(email);
  const normalizedPassword = String(password || "");

  if (
    !normalizedEmail ||
    normalizedEmail.length > MAX_EMAIL_LENGTH ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
  ) {
    return { error: "Enter a valid email address." };
  }

  if (normalizedPassword.length < 10) {
    return { error: "Password must be at least 10 characters long." };
  }

  if (normalizedPassword.length > MAX_PASSWORD_LENGTH) {
    return { error: "Password must be 256 characters or fewer." };
  }

  return {
    email: normalizedEmail,
    password: normalizedPassword,
  };
}

async function checkAuthAttemptRateLimit({
  request,
  response,
  requestPath,
  sendRateLimited,
  getClientIp,
  authRateLimiter,
  trustProxy,
  isLocalHostname,
  isPrivateAddress,
  emailScope = "unknown",
}) {
  if (!authRateLimiter) {
    return true;
  }

  const clientIp = getClientIp(request, { trustProxy, isLocalHostname, isPrivateAddress }) || "unknown";
  const rateLimitState = await authRateLimiter.check(`auth:${clientIp}:${emailScope}`);
  if (!rateLimitState.limited) {
    return true;
  }

  sendRateLimited(response, rateLimitState.retryAfterSeconds, "Too many authentication attempts. Please try again later.");
  return false;
}

export async function resolveAuthenticatedSession({
  token,
  scanRepository,
  authTokenFingerprintSalt,
}) {
  const tokenHash = await fingerprintToken(token, authTokenFingerprintSalt);
  const session = await scanRepository.getAuthSessionByTokenHash(tokenHash);
  if (!session) {
    return null;
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    await scanRepository.deleteAuthSession(session.id);
    return null;
  }

  const user = await scanRepository.getUserById(session.userId);
  if (!user) {
    await scanRepository.deleteAuthSession(session.id);
    return null;
  }

  const touchedSession = await scanRepository.touchAuthSession(session.id);

  return {
    user: buildPublicUser(user),
    session: touchedSession ?? session,
  };
}

export async function handleAuthRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  readJsonBody,
  sendJson,
  sendRateLimited,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  authTokenFingerprintSalt,
  authRateLimiter,
  getClientIp,
  trustProxy,
  isLocalHostname,
  isPrivateAddress,
}) {
  if (requestUrl.pathname === "/api/auth/register") {
    if (request.method !== "POST") {
      sendMethodNotAllowed(response, ["POST"]);
      return;
    }

    try {
      const body = await readJsonBody(request);
      const credentials = validateCredentials(body);
      if ("error" in credentials) {
        sendJson(response, 400, { error: credentials.error });
        return;
      }

      const authAttemptAllowed = await checkAuthAttemptRateLimit({
        request,
        response,
        requestPath: requestUrl.pathname,
        sendRateLimited,
        getClientIp,
        authRateLimiter,
        trustProxy,
        isLocalHostname,
        isPrivateAddress,
        emailScope: credentials.email,
      });
      if (!authAttemptAllowed) {
        return;
      }

      const existing = await scanRepository.getUserByEmail(credentials.email);
      if (existing) {
        sendJson(response, 400, { error: "Unable to create an account with those credentials." });
        return;
      }

      const passwordHash = await hashPassword(credentials.password);
      const user = await scanRepository.createUser({
        email: credentials.email,
        displayName: normalizeDisplayName(body.displayName),
        passwordHash,
      });

      if (!user) {
        sendJson(response, 400, { error: "Unable to create an account with those credentials." });
        return;
      }

      const token = createSessionToken();
      const expiresAt = new Date(Date.now() + getSessionTtlDays() * 24 * 60 * 60 * 1000).toISOString();
      const session = await scanRepository.createAuthSession({
        userId: user.id,
        tokenHash: await fingerprintToken(token, authTokenFingerprintSalt),
        expiresAt,
      });

      sendJson(response, 201, {
        user: buildPublicUser(user),
        session: buildSessionEnvelope(session, token),
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "auth_register");
    }
    return;
  }

  if (requestUrl.pathname === "/api/auth/login") {
    if (request.method !== "POST") {
      sendMethodNotAllowed(response, ["POST"]);
      return;
    }

    try {
      const body = await readJsonBody(request);
      const credentials = validateCredentials(body);
      if ("error" in credentials) {
        sendJson(response, 400, { error: credentials.error });
        return;
      }

      const authAttemptAllowed = await checkAuthAttemptRateLimit({
        request,
        response,
        requestPath: requestUrl.pathname,
        sendRateLimited,
        getClientIp,
        authRateLimiter,
        trustProxy,
        isLocalHostname,
        isPrivateAddress,
        emailScope: credentials.email,
      });
      if (!authAttemptAllowed) {
        return;
      }

      const user = await scanRepository.getUserByEmail(credentials.email);
      const passwordValid = user ? await verifyPassword(credentials.password, user.passwordHash) : false;
      if (!user || !passwordValid) {
        sendJson(response, 401, { error: "Email or password was incorrect." });
        return;
      }

      const token = createSessionToken();
      const expiresAt = new Date(Date.now() + getSessionTtlDays() * 24 * 60 * 60 * 1000).toISOString();
      const session = await scanRepository.createAuthSession({
        userId: user.id,
        tokenHash: await fingerprintToken(token, authTokenFingerprintSalt),
        expiresAt,
      });

      sendJson(response, 200, {
        user: buildPublicUser(user),
        session: buildSessionEnvelope(session, token),
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "auth_login");
    }
    return;
  }

  if (requestUrl.pathname === "/api/auth/session") {
    if (request.method !== "GET") {
      sendMethodNotAllowed(response, ["GET"]);
      return;
    }

    const presentedToken = getPresentedBearerToken(request);
    if (!presentedToken) {
      sendJson(response, 200, { authenticated: false });
      return;
    }

    try {
      const authState = await resolveAuthenticatedSession({
        token: presentedToken,
        scanRepository,
        authTokenFingerprintSalt,
      });
      if (!authState) {
        sendJson(response, 401, { error: "Session is invalid or expired." });
        return;
      }

      sendJson(response, 200, {
        authenticated: true,
        user: authState.user,
        session: buildSessionEnvelope(authState.session),
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "auth_session");
    }
    return;
  }

  if (requestUrl.pathname === "/api/auth/logout") {
    if (request.method !== "POST") {
      sendMethodNotAllowed(response, ["POST"]);
      return;
    }

    const presentedToken = getPresentedBearerToken(request);
    if (!presentedToken) {
      sendJson(response, 200, { ok: true });
      return;
    }

    try {
      const tokenHash = await fingerprintToken(presentedToken, authTokenFingerprintSalt);
      const session = await scanRepository.getAuthSessionByTokenHash(tokenHash);
      if (session) {
        await scanRepository.deleteAuthSession(session.id);
      }
      sendJson(response, 200, { ok: true });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "auth_logout");
    }
  }
}
