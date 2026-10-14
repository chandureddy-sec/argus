import { useState } from "react";
import AreaChartCard from "../components/AreaChartCard";
import BarChartCard from "../components/BarChartCard";
import DataTable from "../components/DataTable";
import DonutCard from "../components/DonutCard";
import KpiCard from "../components/KpiCard";
import { Card, CardHead, Select } from "../components/ui";
import { indicators, kpis } from "../data/sample";

export default function Reports() {
  const [scope, setScope] = useState("All reports");
  const [period, setPeriod] = useState("2025-2026");
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Security report" sub="Attack surface and threat activity across everything you own">
          <Select value={scope} options={["All reports", "Attack surface", "Threat intel", "Response"]} onChange={setScope} label="Report" />
          <Select value={period} options={["2025-2026", "2024-2025", "Last 90 days"]} onChange={setPeriod} label="Period" />
        </CardHead>
        <div className="grid grid-cols-1 divide-y divide-line border-t border-line sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
          {kpis.map((k, i) => (
            <KpiCard key={k.label} kpi={k} first={i === 0} />
          ))}
        </div>
      </Card>

      <AreaChartCard />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <DonutCard />
        <BarChartCard />
      </div>

      <DataTable rows={indicators} />
    </div>
  );
}
