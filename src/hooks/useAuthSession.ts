import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  type StoredAuthSession,
  clearStoredAuthSession,
  getAuthSession,
  getStoredAuthSession,
  loginUser,
  logoutUser,
  registerUser,
} from "@/lib/apiClient";

type AuthMode = "login" | "register";

export const useAuthSession = () => {
  const [authSession, setAuthSession] = useState<StoredAuthSession | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mode, setMode] = useState<AuthMode>("login");

  const refreshSession = useCallback(async () => {
    const stored = await getStoredAuthSession();
    if (!stored?.token) {
      setAuthSession(null);
      setIsLoading(false);
      return null;
    }

    try {
      const payload = await getAuthSession();
      if (!payload.authenticated || !payload.user || !payload.session) {
        setAuthSession(null);
        return null;
      }

      const nextSession: StoredAuthSession = {
        token: stored.token,
        user: payload.user,
        session: {
          createdAt: payload.session.createdAt,
          expiresAt: payload.session.expiresAt,
          ...(payload.session.lastSeenAt ? { lastSeenAt: payload.session.lastSeenAt } : {}),
        },
      };
      setAuthSession(nextSession);
      return nextSession;
    } catch {
      await clearStoredAuthSession();
      setAuthSession(null);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const signIn = useCallback(async (email: string, password: string) => {
    setIsSubmitting(true);
    try {
      const payload = await loginUser({ email, password });
      const nextSession: StoredAuthSession = {
        token: payload.session.token || "",
        user: payload.user,
        session: {
          createdAt: payload.session.createdAt,
          expiresAt: payload.session.expiresAt,
          ...(payload.session.lastSeenAt ? { lastSeenAt: payload.session.lastSeenAt } : {}),
        },
      };
      setAuthSession(nextSession);
      toast.success(`Signed in as ${payload.user.email}.`);
      return nextSession;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not sign in.");
      return null;
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  const signUp = useCallback(async (email: string, password: string, displayName?: string) => {
    setIsSubmitting(true);
    try {
      const payload = await registerUser({ email, password, displayName });
      const nextSession: StoredAuthSession = {
        token: payload.session.token || "",
        user: payload.user,
        session: {
          createdAt: payload.session.createdAt,
          expiresAt: payload.session.expiresAt,
          ...(payload.session.lastSeenAt ? { lastSeenAt: payload.session.lastSeenAt } : {}),
        },
      };
      setAuthSession(nextSession);
      toast.success(`Account ready. Signed in as ${payload.user.email}.`);
      return nextSession;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not create that account.");
      return null;
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  const signOut = useCallback(async () => {
    setIsSubmitting(true);
    try {
      await logoutUser();
      setAuthSession(null);
      toast.success("Signed out.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not sign out cleanly.");
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  return {
    authSession,
    isAuthenticated: Boolean(authSession?.token),
    isLoading,
    isSubmitting,
    mode,
    setMode,
    refreshSession,
    signIn,
    signUp,
    signOut,
  };
};
