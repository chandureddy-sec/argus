import { useEffect, useState } from "react";
import { BrowserRouter, Link, Route, Routes, useLocation } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import { useApi, type Me } from "./lib/api";
import { CrumbsProvider, usePage } from "./lib/page";
import Compare from "./pages/Compare";
import Job from "./pages/Job";
import Monitors from "./pages/Monitors";
import NewScan from "./pages/NewScan";
import Reports from "./pages/Reports";
import ScanView from "./pages/ScanView";
import Scans from "./pages/Scans";

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
    <BrowserRouter basename="/app">
      <Shell />
    </BrowserRouter>
  );
}
