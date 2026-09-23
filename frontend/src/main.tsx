import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { SessionProvider } from "./lib/session";
import Shell from "./components/Shell";
import Landing from "./pages/Landing";
import Explorer from "./pages/Explorer";
import AssetDetail from "./pages/AssetDetail";
import Admin from "./pages/Admin";
import { Risk, Proposals } from "./pages/RiskAndProposals";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <SessionProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/console" element={<Shell />}>
            <Route index element={<Explorer />} />
            <Route path="asset/:id" element={<AssetDetail />} />
            <Route path="proposals" element={<Proposals />} />
            <Route path="risk" element={<Risk />} />
            <Route path="admin" element={<Admin />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </SessionProvider>
  </React.StrictMode>
);
