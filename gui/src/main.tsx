import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import "./index.css";
import App from "./App.tsx";
import { ThemeProvider } from "./components/theme-provider";
import { ReplProvider } from "./context/ReplContext";
import "./i18n.ts";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
        <ReplProvider>
          <BrowserRouter>
            <App />
            <Toaster />
          </BrowserRouter>
        </ReplProvider>
      </ThemeProvider>
    </QueryClientProvider>
  </StrictMode>,
);
