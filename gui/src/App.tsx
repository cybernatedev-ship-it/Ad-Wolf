import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Stats {
  total: number;
  blocked: number;
  allowed: number;
  cached: number;
}

interface TopDomain {
  domain: string;
  count: number;
}

function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [topBlocked, setTopBlocked] = useState<TopDomain[]>([]);

  useEffect(() => {
    invoke<Stats>("get_stats").then(setStats).catch(console.error);
    invoke<TopDomain[]>("get_top_blocked", { limit: 10 })
      .then(setTopBlocked)
      .catch(console.error);
  }, []);

  return (
    <div className="container">
      <header>
        <h1>Ad-Wolf</h1>
        <p className="subtitle">DNS Filter Dashboard</p>
      </header>

      <section className="stats-grid">
        <div className="stat-card">
          <span className="stat-value">{stats?.total ?? "—"}</span>
          <span className="stat-label">Total</span>
        </div>
        <div className="stat-card blocked">
          <span className="stat-value">{stats?.blocked ?? "—"}</span>
          <span className="stat-label">Blocked</span>
        </div>
        <div className="stat-card allowed">
          <span className="stat-value">{stats?.allowed ?? "—"}</span>
          <span className="stat-label">Allowed</span>
        </div>
        <div className="stat-card cached">
          <span className="stat-value">{stats?.cached ?? "—"}</span>
          <span className="stat-label">Cached</span>
        </div>
      </section>

      <section>
        <h2>Top Blocked Domains</h2>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Domain</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {topBlocked.map((d, i) => (
              <tr key={d.domain}>
                <td>{i + 1}</td>
                <td>{d.domain}</td>
                <td>{d.count}</td>
              </tr>
            ))}
            {topBlocked.length === 0 && (
              <tr>
                <td colSpan={3}>No blocked domains yet</td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}

export default App;
