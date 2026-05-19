// packetsentry-web/frontend/src/screens/Landing.tsx
import { api } from "../api/client";
import { useAuthStore } from "../store/authStore";
import { PixelShield } from "../components/PixelIcons";

const STATS = [
  { label: "ML Models", value: "7" },
  { label: "Tests", value: "241" },
  { label: "NSL-KDD F1", value: "99%" },
  { label: "Detectors", value: "Parallel" },
];

const STACK = [
  "XGBoost + SHAP",
  "GraphSAGE GNN (scratch)",
  "Transformer AE",
  "Isolation Forest",
  "Aho-Corasick (scratch)",
  "FastAPI + WebSocket",
  "React + TypeScript",
  "DuckDB + ChromaDB",
];

export function Landing({ onLogin }: { onLogin: () => void }) {
  const login = useAuthStore((s) => s.login);

  async function handleDemo() {
    const { access_token, role } = await api.demoToken();
    login(access_token, role as "admin" | "demo");
  }

  return (
    <div className="min-h-screen bg-[#C0C0C0] flex flex-col">
      {/* Nav */}
      <header className="h-11 border-b-2 border-black bg-white flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-2">
          <PixelShield size={18} className="text-gray-900" />
          <span className="font-black text-sm tracking-wide uppercase">PacketSentry</span>
        </div>
        <div className="flex gap-2">
          <a
            href="https://github.com/shreyshringare/network-intrusion-detection"
            target="_blank"
            rel="noreferrer"
            className="border-2 border-black px-3 py-1 text-xs font-bold uppercase tracking-wide hover:bg-black hover:text-white transition-colors duration-100"
          >
            GitHub
          </a>
          <button
            onClick={onLogin}
            className="border-2 border-black bg-black text-[#00FF41] px-3 py-1 text-xs font-bold uppercase tracking-wide hover:bg-[#00FF41] hover:text-black transition-colors duration-100"
          >
            Login
          </button>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-16 text-center">
        <div className="border-2 border-black bg-white shadow-brutalist px-8 py-10 max-w-2xl w-full">
          <p className="font-mono text-xs text-[#00FF41] bg-black px-2 py-1 inline-block mb-4 tracking-widest">
            [&gt;] SYSTEM ONLINE
          </p>
          <h1 className="font-black text-4xl uppercase tracking-tight leading-none mb-3">
            PacketSentry
          </h1>
          <p className="font-mono text-sm text-gray-600 mb-6">
            Network Intrusion Detection System — 7-model ML ensemble,
            SHAP-explained alerts, real-time dashboard
          </p>

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-0 border-2 border-black mb-6">
            {STATS.map((s, i) => (
              <div
                key={s.label}
                className={`px-4 py-3 text-center ${i < STATS.length - 1 ? "border-r-2 border-black" : ""}`}
              >
                <div className="font-black text-2xl text-[#00FF41] bg-black px-1">{s.value}</div>
                <div className="text-[10px] font-bold uppercase tracking-wide text-gray-500 mt-1">{s.label}</div>
              </div>
            ))}
          </div>

          {/* CTA */}
          <div className="flex gap-3 justify-center">
            <button
              onClick={handleDemo}
              className="bg-black text-[#00FF41] border-2 border-black font-black uppercase tracking-wide px-6 py-3 text-sm hover:bg-[#00FF41] hover:text-black transition-colors duration-100"
            >
              TRY DEMO
            </button>
          </div>
        </div>

        {/* Stack grid */}
        <div className="mt-8 max-w-2xl w-full">
          <p className="font-mono text-[10px] text-gray-600 uppercase tracking-widest mb-3">// TECH STACK</p>
          <div className="grid grid-cols-4 gap-2">
            {STACK.map((item) => (
              <div key={item} className="border-2 border-black bg-white px-3 py-2 text-[10px] font-bold uppercase tracking-wide text-center">
                {item}
              </div>
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="h-6 border-t-2 border-black bg-white flex items-center justify-between px-4 text-[9px] text-gray-400 font-mono shrink-0">
        <span>PACKETSENTRY // NIDS v1.0</span>
        <span>241 TESTS PASSING // 7-MODEL ENSEMBLE // SHAP-EXPLAINED</span>
      </footer>
    </div>
  );
}
