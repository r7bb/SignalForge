"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { api, ApiError, saveSession } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@signalforge.local");
  const [password, setPassword] = useState("");
  const [tenant, setTenant] = useState("acme");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await api.login(email, password, tenant || undefined);
      saveSession(session);
      router.replace("/");
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="card login-card">
        <div className="brand" style={{ marginBottom: 18 }}>
          <span className="brand-mark" aria-hidden="true">
            SF
          </span>
          SignalForge
        </div>

        <form onSubmit={submit}>
          <div className="form-field">
            <label htmlFor="tenant">Tenant</label>
            <input
              id="tenant"
              className="input"
              value={tenant}
              onChange={(event) => setTenant(event.target.value)}
              autoComplete="organization"
            />
          </div>
          <div className="form-field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              className="input"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="username"
              required
            />
          </div>
          <div className="form-field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              className="input"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <p className="error" style={{ marginBottom: 12 }}>
              {error}
            </p>
          )}

          <button type="submit" className="button primary" style={{ width: "100%" }} disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="notice" style={{ marginTop: 16 }}>
          The bootstrap administrator is created from
          <span className="mono"> SIGNALFORGE_BOOTSTRAP_ADMIN_EMAIL</span> and
          <span className="mono"> SIGNALFORGE_BOOTSTRAP_ADMIN_PASSWORD</span>. Change them
          before exposing an instance.
        </p>
      </div>
    </div>
  );
}
