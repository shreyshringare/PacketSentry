// packetsentry-web/frontend/src/screens/Login.tsx
import React, { useState } from "react";
import { api } from "../api/client";
import { useAuthStore } from "../store/authStore";

export function Login() {
  const login = useAuthStore((s) => s.login);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { access_token, role } = await api.login(password);
      login(access_token, role as "admin" | "demo");
    } catch {
      setError("Incorrect password.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDemo() {
    setLoading(true);
    try {
      const { access_token, role } = await api.demoToken();
      login(access_token, role as "admin" | "demo");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#C0C0C0] flex items-center justify-center">
      <div className="bg-white border-2 border-black shadow-brutalist p-8 w-full max-w-sm">
        <h1 className="font-black text-xl uppercase tracking-widest mb-1">PACKETSENTRY</h1>
        <p className="text-xs font-mono text-gray-500 mb-6">// NIDS ACCESS CONTROL</p>

        <form onSubmit={handleLogin} className="flex flex-col gap-3">
          <div className="flex items-center border-2 border-black bg-black px-2 py-2">
            <span className="text-[#00FF41] font-mono text-xs shrink-0 mr-2">admin@nids:~$</span>
            <input
              type="password"
              placeholder="enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="flex-1 bg-transparent text-[#00FF41] font-mono text-xs outline-none placeholder-gray-600"
              autoFocus
            />
          </div>

          {error && (
            <p className="text-red-600 font-mono text-xs border border-red-600 px-2 py-1">
              [ERR] {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading || !password}
            className="bg-black text-[#00FF41] border-2 border-black font-bold uppercase tracking-wide text-xs py-2 hover:bg-[#00FF41] hover:text-black disabled:opacity-40 transition-colors duration-100"
          >
            {loading ? "AUTHENTICATING..." : "LOGIN"}
          </button>
        </form>

        <div className="mt-4 pt-4 border-t-2 border-black">
          <button
            onClick={handleDemo}
            disabled={loading}
            className="w-full bg-white text-gray-700 border-2 border-black font-bold uppercase tracking-wide text-xs py-2 hover:bg-black hover:text-white transition-colors duration-100"
          >
            TRY DEMO (READ-ONLY)
          </button>
          <p className="text-[9px] text-gray-400 font-mono mt-2 text-center">
            Demo mode: pre-recorded data, no live capture
          </p>
        </div>
      </div>
    </div>
  );
}
