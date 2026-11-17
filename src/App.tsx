import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppProvider } from "./context/AppContext";
import { Layout } from "./components/layout/Layout";
import OverviewPage from "./pages/Overview";
import FindingsPage from "./pages/Findings";
import AssetsPage from "./pages/Assets";
import ProtocolsPage from "./pages/Protocols";
import PacketViewerPage from "./pages/PacketViewer";
import ReportPage from "./pages/Report";

export default function App() {
  return (
    <AppProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/protocols" element={<ProtocolsPage />} />
            <Route path="/packets" element={<PacketViewerPage />} />
            <Route path="/report" element={<ReportPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AppProvider>
  );
}
