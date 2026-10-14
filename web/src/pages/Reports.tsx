import AreaChartCard from "../components/AreaChartCard";
import BarChartCard from "../components/BarChartCard";
import DataTable from "../components/DataTable";
import DonutCard from "../components/DonutCard";
import KpiCard from "../components/KpiCard";
import { Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { useApi, type Kpi } from "../lib/api";

export default function Reports() {
  const kpis = useApi<Kpi[]>("kpis");
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Security report" sub="Attack surface and threat activity across everything you own">
          <button className="btn-ghost h-8 text-[13px]" onClick={kpis.reload} disabled={kpis.loading}>
            Refresh
          </button>
        </CardHead>
        {kpis.error && !kpis.data ? (
          <Failed error={kpis.error} onRetry={kpis.reload} />
        ) : (
          <div className="grid grid-cols-1 divide-y divide-line border-t border-line sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
            {kpis.data
              ? kpis.data.map((k, i) => <KpiCard key={k.key} kpi={k} first={i === 0} />)
              : Array.from({ length: 4 }, (_, i) => (
                  <div key={i} className="space-y-3 py-4 sm:px-5">
                    <Skeleton className="h-5 w-32" />
                    <Skeleton className="h-7 w-24" />
                  </div>
                ))}
          </div>
        )}
      </Card>

      <AreaChartCard />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <DonutCard />
        <BarChartCard />
      </div>

      <DataTable />
    </div>
  );
}
