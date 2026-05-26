import { useState } from "react";
import { KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { StoredAuthSession } from "@/lib/apiClient";

interface AuthCardProps {
  authSession: StoredAuthSession | null;
  isLoading: boolean;
  isSubmitting: boolean;
  mode: "login" | "register";
  setMode: (mode: "login" | "register") => void;
  signIn: (email: string, password: string) => Promise<unknown>;
  signUp: (email: string, password: string, displayName?: string) => Promise<unknown>;
  signOut: () => Promise<void>;
}

export const AuthCard = ({
  authSession,
  isLoading,
  isSubmitting,
  mode,
  setMode,
  signIn,
  signUp,
  signOut,
}: AuthCardProps) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  const handleSubmit = async () => {
    if (mode === "login") {
      const result = await signIn(email, password);
      if (result) {
        setPassword("");
      }
      return;
    }

    const result = await signUp(email, password, displayName || undefined);
    if (result) {
      setPassword("");
    }
  };

  if (authSession) {
    return (
      <div className="h-full rounded-[1.8rem] border border-emerald-400/15 bg-zinc-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
        <div className="mb-4 flex items-center justify-between gap-3">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-emerald-300">Signed in</p>
          <ShieldCheck className="h-5 w-5 text-emerald-300" />
        </div>
        <div className="space-y-4">
          <div className="rounded-[1.2rem] border border-white/10 bg-white/[0.04] px-4 py-4">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 rounded-full bg-emerald-400/12 p-2 text-emerald-300">
                <UserRound className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-white">
                  {authSession.user.displayName || authSession.user.email}
                </p>
                <p className="mt-1 break-all text-xs leading-5 text-zinc-400">{authSession.user.email}</p>
              </div>
            </div>
          </div>
          <div className="rounded-[1.2rem] border border-white/10 bg-white/[0.04] px-4 py-4 text-sm leading-6 text-zinc-300">
            Saved scans, monitoring targets, and report history now follow your account instead of being tied to this browser only.
          </div>
          <div className="flex items-center justify-between gap-3 rounded-[1.2rem] border border-white/10 bg-white/[0.04] px-4 py-4 text-xs text-zinc-400">
            <span>Session valid until</span>
            <span className="text-zinc-200">
              {new Date(authSession.session.expiresAt).toLocaleDateString()}
            </span>
          </div>
          <Button
            type="button"
            variant="outline"
            className="w-full border-white/10 bg-white/[0.04] text-zinc-100 hover:bg-white/[0.08]"
            onClick={() => void signOut()}
            disabled={isSubmitting}
          >
            Sign out
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full rounded-[1.8rem] border border-white/10 bg-zinc-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
      <div className="mb-4 flex items-center justify-between gap-3">
        <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Account</p>
        <KeyRound className="h-5 w-5 text-[#d89a63]" />
      </div>
      <div className="space-y-4">
        <div className="rounded-[1.2rem] border border-white/10 bg-white/[0.04] px-4 py-4 text-sm leading-6 text-zinc-300">
          Sign in to keep scans, monitoring targets, and history attached to your account across browsers and future mobile clients.
        </div>
        <Tabs value={mode} onValueChange={(value) => setMode(value as "login" | "register")} className="space-y-4">
          <TabsList className="grid w-full grid-cols-2 rounded-xl border border-white/10 bg-zinc-950/50 p-1">
            <TabsTrigger value="login" className="rounded-lg data-[state=active]:bg-white/[0.08]">Sign in</TabsTrigger>
            <TabsTrigger value="register" className="rounded-lg data-[state=active]:bg-white/[0.08]">Create account</TabsTrigger>
          </TabsList>
        </Tabs>
        <div className="space-y-3">
          {mode === "register" ? (
            <Input
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              placeholder="Name (optional)"
              className="border-white/10 bg-zinc-950/45 text-zinc-100 placeholder:text-zinc-500"
            />
          ) : null}
          <Input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            type="email"
            placeholder="Email address"
            className="border-white/10 bg-zinc-950/45 text-zinc-100 placeholder:text-zinc-500"
          />
          <Input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
            placeholder={mode === "register" ? "Password (10+ characters)" : "Password"}
            className="border-white/10 bg-zinc-950/45 text-zinc-100 placeholder:text-zinc-500"
          />
        </div>
        <Button
          type="button"
          className="w-full bg-[#b56a2c] text-white hover:bg-[#9d5a23]"
          onClick={() => void handleSubmit()}
          disabled={isSubmitting || isLoading || !email || !password}
        >
          {isSubmitting ? "Working..." : mode === "login" ? "Sign in" : "Create account"}
        </Button>
        <p className="text-xs leading-5 text-zinc-500">
          You can still use the app anonymously, but account mode is now the preferred ownership path.
        </p>
      </div>
    </div>
  );
};
