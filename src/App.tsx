import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import { ReportPage } from "./pages/ReportPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { recordPageLoad } from "./lib/apiClient";

const queryClient = new QueryClient();

const App = () => {
  useEffect(() => {
    recordPageLoad();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <div className="noise">
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/report/:scanId" element={<ReportPage />} />
              <Route path="/privacy" element={<PrivacyPage />} />
            </Routes>
          </div>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
