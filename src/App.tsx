import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import Index from "./pages/Index";
import Telemetry from "./pages/Telemetry";
import { recordPageLoad } from "./lib/apiClient";

const queryClient = new QueryClient();

const PageLoadRecorder = () => {
  const location = useLocation();

  useEffect(() => {
    if (location.pathname === "/telemetry") {
      return;
    }
    recordPageLoad();
  }, [location.pathname]);

  return null;
};

const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <PageLoadRecorder />
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/telemetry" element={<Telemetry />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
