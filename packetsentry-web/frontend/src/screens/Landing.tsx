// packetsentry-web/frontend/src/screens/Landing.tsx
import { useState } from "react";
import { api } from "../api/client";
import { useAuthStore } from "../store/authStore";
import { PixelShield } from "../components/PixelIcons";

const STATS = [
  { value: "7", label: "ML Models", sub: "Ensemble inference" },
  { value: "241", label: "Tests Passing", sub: "Full coverage" },
  { value: "99%", label: "NSL-KDD F1", sub: "Benchmark dataset" },
  { value: "<1ms", label: "Alert Latency", sub: "Per-packet scoring" },
];

const FEATURES = [
  {
    step: "01",
    title: "Capture",
    desc: "Raw packets off the wire via libpcap. Protocol dissection: Ethernet → IP → TCP/UDP → DNS.",
  },
  {
    step: "02",
    title: "Analyze",
    desc: "7-model ensemble: XGBoost, GNN, Transformer AE, Isolation Forest, Z-Score — run in parallel.",
  },
  {
    step: "03",
    title: "Explain",
    desc: "Every alert ships with SHAP feature attribution. No black-box decisions — every call is justified.",
  },
];

const STACK_GROUPS = [
  { group: "ML", items: ["XGBoost + SHAP", "GraphSAGE GNN", "Transformer AE", "Isolation Forest"] },
  { group: "Backend", items: ["FastAPI", "WebSocket", "DuckDB", "ChromaDB"] },
  { group: "From Scratch", items: ["Aho-Corasick Trie", "GraphSAGE MPNN", "Textual TUI", "CLI (Typer)"] },
];

export function Landing({ onLogin }: { onLogin: () => void }) {
  const login = useAuthStore((s) => s.login);
  const [loading, setLoading] = useState(false);
  const [demoError, setDemoError] = useState("");

  async function handleDemo() {
    setLoading(true);
    setDemoError("");
    try {
      const { access_token, role } = await api.demoToken();
      login(access_token, role as "admin" | "demo");
    } catch {
      setDemoError("Backend offline — start the API server first.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#C0C0C0] flex flex-col">

      {/* ── Navbar ─────────────────────────────────── */}
      <header className="h-12 border-b-2 border-black bg-white flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-2">
          <PixelShield size={20} className="text-black" />
          <span className="font-black text-sm tracking-widest uppercase">PacketSentry</span>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="https://github.com/shreyshringare/PacketSentry"
            target="_blank"
            rel="noreferrer"
            className="text-[11px] font-bold uppercase tracking-wide text-gray-500 hover:text-black transition-colors"
          >
            GitHub
          </a>
          <button
            onClick={onLogin}
            className="border-2 border-black bg-black text-[#00FF41] px-4 py-1.5 text-xs font-black uppercase tracking-widest hover:bg-[#00FF41] hover:text-black transition-colors duration-100"
          >
            Login
          </button>
        </div>
      </header>

      <main className="flex-1 flex flex-col">

        {/* ── Hero ───────────────────────────────────── */}
        <section className="flex flex-col items-center justify-center px-6 pt-16 pb-10 text-center">
          <span className="font-mono text-[10px] text-[#00FF41] bg-black px-3 py-1 tracking-[0.25em] uppercase mb-5 inline-block">
            [&gt;] REAL-TIME NETWORK INTRUSION DETECTION
          </span>

          <h1 className="font-black text-6xl uppercase tracking-tight leading-none mb-4 text-black">
            Packet<span className="text-black">Sentry</span>
          </h1>

          <p className="font-mono text-sm text-gray-700 max-w-lg mb-8 leading-relaxed">
            A production-grade NIDS with a 7-model ML ensemble, SHAP-explained alerts,
            real-time WebSocket dashboard, and full CLI control surface.
          </p>

          <div className="flex gap-3">
            <button
              onClick={handleDemo}
              disabled={loading}
              className="bg-black text-[#00FF41] border-2 border-black font-black uppercase tracking-widest px-8 py-3 text-sm hover:bg-[#00FF41] hover:text-black disabled:opacity-50 transition-colors duration-100 shadow-brutalist"
            >
              {loading ? "LOADING..." : "TRY DEMO"}
            </button>
            <button
              onClick={onLogin}
              className="bg-white text-black border-2 border-black font-black uppercase tracking-widest px-8 py-3 text-sm hover:bg-black hover:text-white transition-colors duration-100"
            >
              Login
            </button>
          </div>

          {demoError && (
            <p className="text-red-600 font-mono text-[10px] border border-red-600 px-3 py-1 mt-2">
              [ERR] {demoError}
            </p>
          )}

          <p className="text-[9px] font-mono text-gray-500 mt-3 tracking-wide">
            Demo mode: pre-recorded data · no live capture · read-only
          </p>
        </section>

        {/* ── Stats bar ──────────────────────────────── */}
        <section className="border-y-2 border-black bg-white">
          <div className="max-w-4xl mx-auto grid grid-cols-4 divide-x-2 divide-black">
            {STATS.map((s) => (
              <div key={s.label} className="px-6 py-5 text-center">
                <div className="font-black text-3xl text-black leading-none">{s.value}</div>
                <div className="font-bold text-xs uppercase tracking-widest text-black mt-1">{s.label}</div>
                <div className="font-mono text-[9px] text-gray-400 mt-0.5">{s.sub}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ── How it works ───────────────────────────── */}
        <section className="px-6 py-12">
          <div className="max-w-4xl mx-auto">
            <p className="font-mono text-[10px] text-gray-600 uppercase tracking-[0.2em] mb-6 text-center">
              // HOW IT WORKS
            </p>
            <div className="grid grid-cols-3 gap-4">
              {FEATURES.map((f) => (
                <div key={f.step} className="bg-white border-2 border-black p-5 shadow-brutalist">
                  <div className="font-mono text-[10px] text-gray-400 mb-2">{f.step}</div>
                  <div className="font-black text-lg uppercase tracking-wide mb-2">{f.title}</div>
                  <div className="font-mono text-[11px] text-gray-600 leading-relaxed">{f.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Tech stack ─────────────────────────────── */}
        <section className="px-6 pb-12">
          <div className="max-w-4xl mx-auto">
            <p className="font-mono text-[10px] text-gray-600 uppercase tracking-[0.2em] mb-6 text-center">
              // TECH STACK
            </p>
            <div className="grid grid-cols-3 gap-4">
              {STACK_GROUPS.map((g) => (
                <div key={g.group} className="bg-white border-2 border-black">
                  <div className="bg-black text-[#00FF41] font-mono text-[10px] tracking-widest px-3 py-1.5 uppercase">
                    {g.group}
                  </div>
                  <ul className="divide-y divide-gray-100">
                    {g.items.map((item) => (
                      <li key={item} className="px-3 py-2 font-mono text-[11px] text-gray-700">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

      </main>

      {/* ── Footer ─────────────────────────────────── */}
      <footer className="border-t-2 border-black bg-black py-3 px-6 flex items-center justify-between shrink-0">
        <span className="font-mono text-[9px] text-[#00FF41] tracking-widest uppercase">
          PacketSentry // NIDS v1.0
        </span>
        <span className="font-mono text-[9px] text-gray-500 tracking-wide">
          241 tests · 7 models · SHAP-explained
        </span>
      </footer>

    </div>
  );
}
