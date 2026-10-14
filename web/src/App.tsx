import { useEffect, useState } from "react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import { useApi, type Me } from "./lib/api";
import Reports from "./pages/Reports";

export default function App() {
  const [menu, setMenu] = useState(false);
  const me = useApi<Me>("me").data;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="min-h-full">
      <Sidebar open={menu} onClose={() => setMenu(false)} me={me} />
      <div className="flex min-h-full flex-col lg:pl-[240px]">
        <Topbar onMenu={() => setMenu(true)} me={me} />
        <main className="flex-1">
          <Reports />
        </main>
      </div>
    </div>
  );
}
