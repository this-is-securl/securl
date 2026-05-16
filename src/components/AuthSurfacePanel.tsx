import { KeyRound, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
import { getAuthSurfaceSummary } from "@/lib/passiveSurface";
import { HtmlSecurityInfo } from "@/types/analysis";

interface AuthSurfacePanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const AuthSurfacePanel = ({ htmlSecurity }: AuthSurfacePanelProps) => {
  const summary = getAuthSurfaceSummary(htmlSecurity);

  if (!summary.authPaths.length && !summary.passwordFormCount) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            Auth Surface
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm leading-6 text-zinc-300">
            No obvious auth-adjacent paths or password form signals were detected from the fetched page.
          </p>
          <div className="grid gap-4 md:grid-cols-4">
            <StatBox label="Auth paths" value={<p className="text-2xl font-semibold">0</p>} />
            <StatBox label="Password forms" value={<p className="text-2xl font-semibold">0</p>} />
            <StatBox label="External password posts" value={<p className="text-2xl font-semibold">0</p>} />
            <StatBox label="Insecure password posts" value={<p className="text-2xl font-semibold">0</p>} />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5" />
          Auth Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sm leading-6 text-zinc-300">{summary.summary}</p>

        <div className="grid gap-4 md:grid-cols-4">
          <StatBox label="Auth paths" value={<p className="text-2xl font-semibold">{summary.authPaths.length}</p>} />
          <StatBox label="Password forms" value={<p className="text-2xl font-semibold">{summary.passwordFormCount}</p>} />
          <StatBox label="External password posts" value={<p className="text-2xl font-semibold">{summary.externalPasswordForms.length}</p>} />
          <StatBox label="Insecure password posts" value={<p className="text-2xl font-semibold">{summary.insecurePasswordForms}</p>} />
        </div>

        {summary.authPaths.length ? (
          <StatBox
            label="Observed auth-adjacent paths"
            value={
              <div className="flex flex-wrap gap-2">
                {summary.authPaths.map((item) => (
                  <TruncatedChip key={item.path} value={`${item.path} · ${item.category}`} />
                ))}
              </div>
            }
          />
        ) : null}

        {summary.externalPasswordForms.length ? (
          <StatusAlert variant="warning" icon={<ShieldAlert />}>
            Password handling appears to involve an external origin. That can be legitimate for SSO, but it is worth
            confirming against the expected identity flow.
          </StatusAlert>
        ) : null}
      </CardContent>
    </Card>
  );
};
