import { useEffect, useState } from "react";
import { BrowserRouter, Link, Route, Routes, useLocation } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import { useApi, type Me } from "./lib/api";
import { CrumbsProvider, usePage } from "./lib/page";
import { ThemeProvider } from "./lib/theme";
import Assets from "./pages/Assets";
import Attack from "./pages/Attack";
import EntityView from "./pages/EntityView";
import Landscape from "./pages/Landscape";
import Login from "./pages/Login";
import SearchPage from "./pages/SearchPage";
import VulnView from "./pages/VulnView";
import Vulnerabilities from "./pages/Vulnerabilities";
import Blocklist from "./pages/Blocklist";
import BulkCheck from "./pages/BulkCheck";
import Cases from "./pages/Cases";
import CaseView from "./pages/CaseView";
import Compare from "./pages/Compare";
import FeedForm from "./pages/FeedForm";
import Feeds from "./pages/Feeds";
import FeedView from "./pages/FeedView";
import Indicators from "./pages/Indicators";
import IndicatorView from "./pages/IndicatorView";
import Job from "./pages/Job";
import Monitors from "./pages/Monitors";
import NewScan from "./pages/NewScan";
import Reports from "./pages/Reports";
import ScanView from "./pages/ScanView";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";
import Verify from "./pages/Verify";

function NotFound() {
  usePage("Not found");
  return (
    <div className="mx-auto max-w-lg px-6 py-24 text-center">
      <p className="text-[56px] font-bold text-ink-faint">404</p>
      <p className="mt-2 text-ink-muted">This page doesn't exist.</p>
      <Link to="/" className="btn-primary mt-6">
        Back to the dashboard
      </Link>
    </div>
  );
}

function Shell() {
  const [menu, setMenu] = useState(false);
  const [crumbs, setCrumbs] = useState<string[]>(["Reports"]);
  const me = useApi<Me>("me").data;
  const loc = useLocation();
  useEffect(() => setMenu(false), [loc.pathname]); // close the phone menu after navigating
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <CrumbsProvider set={setCrumbs}>
      <div className="min-h-full">
        <Sidebar open={menu} onClose={() => setMenu(false)} me={me} />
        <div className="flex min-h-full flex-col lg:pl-[240px]">
          <Topbar onMenu={() => setMenu(true)} me={me} crumbs={crumbs} />
          <main className="flex-1">
            <Routes>
              <Route path="/" element={<Reports />} />
              <Route path="/scans" element={<Scans me={me} />} />
              <Route path="/scans/new" element={<NewScan me={me} />} />
              <Route path="/scans/job/:id" element={<Job me={me} />} />
              <Route path="/scans/view/:ref" element={<ScanView me={me} />} />
              <Route path="/scans/compare" element={<Compare />} />
              <Route path="/monitors" element={<Monitors me={me} />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/verify" element={<Verify me={me} />} />
              <Route path="/bulk" element={<BulkCheck me={me} />} />
              <Route path="/indicators" element={<Indicators />} />
              <Route path="/indicators/:id" element={<IndicatorView me={me} />} />
              <Route path="/blocklist" element={<Blocklist me={me} />} />
              <Route path="/cases" element={<Cases me={me} />} />
              <Route path="/cases/:id" element={<CaseView me={me} />} />
              <Route path="/feeds" element={<Feeds me={me} />} />
              <Route path="/feeds/new" element={<FeedForm me={me} />} />
              <Route path="/feeds/:name" element={<FeedView me={me} />} />
              <Route path="/feeds/:name/edit" element={<FeedForm me={me} />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/audit" element={<Settings initialTab="audit" />} />
              <Route path="/landscape" element={<Landscape />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/vulnerabilities/:cve" element={<VulnView me={me} />} />
              <Route path="/attack" element={<Attack />} />
              <Route path="/entities/:ref" element={<EntityView />} />
              <Route path="/search" element={<SearchPage />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
      </div>
    </CrumbsProvider>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter basename="/app">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Shell />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}
