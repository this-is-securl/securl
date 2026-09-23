import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import Index from "./pages/Index";
import { ReportPage } from "./pages/ReportPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { SharedLinkPage } from "./pages/SharedLinkPage";
import { recordPageLoad } from "./lib/apiClient";
import { parseAppRoute } from "./lib/appRoute";

const queryClient = new QueryClient();

const App = () => {
  const route = parseAppRoute(window.location.pathname);

  useEffect(() => {
    // Shared-result views are counted by the public API without sending the
    // unguessable result id through generic page telemetry.
    if (route.kind !== "shared-link") recordPageLoad();
  }, [route.kind]);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <div className="noise">
          {route.kind === "home" && <Index />}
          {route.kind === "report" && <ReportPage scanId={route.scanId} />}
          {route.kind === "privacy" && <PrivacyPage />}
          {route.kind === "shared-link" && <SharedLinkPage publicId={route.publicId} />}
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
