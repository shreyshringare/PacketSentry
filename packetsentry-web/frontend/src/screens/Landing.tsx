// packetsentry-web/frontend/src/screens/Landing.tsx
import { useState } from "react";
import { api } from "../api/client";
import { useAuthStore } from "../store/authStore";
import { PixelShield } from "../components/PixelIcons";
import { Footer } from "../components/Footer";

const STATS = [
  { value: "7", label: "ML Models", sub: "Confidence-weighted ensemble" },
  { value: "O(n)", label: "Pattern Match", sub: "Aho-Corasick from scratch" },
  { value: "100%", label: "SHAP Coverage", sub: "Every alert explained" },
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

  function handleOfflineDemo() {
    // Mint a synthetic demo token and enter the dashboard.
    // useDemoAlerts() in App.tsx will detect the backend is offline
    // and load MOCK_ALERTS / MOCK_FLOWS / MOCK_STATS automatically.
    login("offline-demo", "demo");
    onLogin();
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
          <span
            className="font-mono text-[10px] text-[#00FF41] bg-black px-3 py-1 tracking-[0.25em] uppercase mb-5 inline-block"
            style={{ animation: "fadeInUp 0.4s ease-out both", animationDelay: "0ms" }}
          >
            [&gt;] REAL-TIME NETWORK INTRUSION DETECTION
          </span>

          <h1
            className="font-black text-6xl uppercase tracking-tight leading-none mb-4 text-black"
            style={{ animation: "fadeInUp 0.4s ease-out both", animationDelay: "100ms" }}
          >
            Packet<span className="text-black">Sentry</span>
          </h1>

          <p
            className="font-mono text-sm text-gray-700 max-w-lg mb-8 leading-relaxed"
            style={{ animation: "fadeInUp 0.4s ease-out both", animationDelay: "200ms" }}
          >
            A production-grade NIDS with a 7-model ML ensemble, SHAP-explained alerts,
            real-time WebSocket dashboard, and full CLI control surface.
          </p>

          <div className="flex gap-3" style={{ animation: "fadeInUp 0.4s ease-out both", animationDelay: "300ms" }}>
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
            <div className="flex flex-col items-center gap-2 mt-2">
              <p className="text-red-600 font-mono text-[10px] border border-red-600 px-3 py-1">
                [ERR] {demoError}
              </p>
              <button
                onClick={handleOfflineDemo}
                className="border-2 border-black bg-black text-[#00FF41] font-mono text-[10px] uppercase tracking-widest px-4 py-1.5 hover:bg-[#00FF41] hover:text-black transition-colors duration-100"
              >
                Load Demo Data Offline →
              </button>
            </div>
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

        {/* ── Run Locally ────────────────────────────── */}
        <section className="px-6 pb-10">
          <div className="max-w-4xl mx-auto">
            <div className="bg-black border-2 border-black p-6">
              <p className="font-mono text-[10px] text-[#00FF41] uppercase tracking-[0.2em] mb-4">
                // RUN LOCALLY — FULL LIVE CAPTURE
              </p>
              <p className="font-mono text-[11px] text-gray-400 mb-5 leading-relaxed">
                Live packet capture requires raw socket access (libpcap/Npcap) — unavailable in cloud environments.
                Clone and run locally to unlock the full pipeline: live capture → 7-model ensemble → real-time alerts.
              </p>
              <div className="bg-[#111] border border-gray-700 p-4 font-mono text-[11px] text-[#00FF41] mb-5 space-y-1">
                <div><span className="text-gray-500"># </span>clone + install</div>
                <div>git clone https://github.com/shreyshringare/PacketSentry.git</div>
                <div>cd PacketSentry &amp;&amp; pip install -e .</div>
                <div className="pt-2"><span className="text-gray-500"># </span>replay a PCAP (no root required)</div>
                <div>packetsentry replay attack.pcap</div>
                <div className="pt-2"><span className="text-gray-500"># </span>live capture (Windows: Npcap · Linux: sudo)</div>
                <div>packetsentry live --interface eth0</div>
              </div>
              <div className="flex gap-3">
                <a
                  href="https://github.com/shreyshringare/PacketSentry"
                  target="_blank"
                  rel="noreferrer"
                  className="bg-[#00FF41] text-black border-2 border-[#00FF41] font-black uppercase tracking-widest px-6 py-2.5 text-xs hover:bg-black hover:text-[#00FF41] transition-colors duration-100"
                >
                  View on GitHub
                </a>
                <a
                  href="https://github.com/shreyshringare/PacketSentry#-quick-start"
                  target="_blank"
                  rel="noreferrer"
                  className="bg-transparent text-[#00FF41] border-2 border-[#00FF41] font-black uppercase tracking-widest px-6 py-2.5 text-xs hover:bg-[#00FF41] hover:text-black transition-colors duration-100"
                >
                  Quick Start Guide →
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* ── Tech stack ─────────────────────────────── */}
        <section className="px-6 pb-12">
          <div className="max-w-4xl mx-auto">
            <p className="font-mono text-[10px] text-gray-600 uppercase tracking-[0.2em] mb-4 text-center">
              // TECH STACK
            </p>
            <div className="bg-black border-2 border-black p-5 font-mono text-[11px]">
              <div className="text-gray-500 mb-3 text-[10px]">$ cat stack.conf</div>
              {STACK_GROUPS.map((g) => (
                <div key={g.group} className="flex gap-0 mb-2 last:mb-0">
                  <span className="text-[#00FF41] w-28 shrink-0 uppercase tracking-widest text-[10px] pt-px">{g.group}</span>
                  <span className="text-gray-400 mr-2 shrink-0">:</span>
                  <span className="text-gray-200">{g.items.join(" · ")}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

      </main>

      {/* ── Footer ─────────────────────────────────── */}
      <Footer variant="landing" />

    </div>
  );
}
