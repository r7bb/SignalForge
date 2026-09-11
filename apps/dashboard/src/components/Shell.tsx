"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";

import { clearSession, loadSession } from "@/lib/api";
import type { Session } from "@/lib/types";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/incidents", label: "Incidents" },
  { href: "/alerts", label: "Alerts" },
  { href: "/detections", label: "Detections" },
  { href: "/supply-chain", label: "Supply chain" },
  { href: "/lab", label: "Lab" },
];

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);

  useEffect(() => {
    const current = loadSession();
    setSession(current);
    if (!current && pathname !== "/login") {
      router.replace("/login");
    }
    const stored = window.localStorage.getItem("signalforge.theme");
    if (stored === "light" || stored === "dark") {
      setTheme(stored);
      document.documentElement.dataset.theme = stored;
    }
  }, [pathname, router]);

  function toggleTheme() {
    const next =
      theme === "dark"
        ? "light"
        : theme === "light"
          ? "dark"
          : window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "light"
            : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("signalforge.theme", next);
  }

  function signOut() {
    clearSession();
    router.replace("/login");
  }

  if (pathname === "/login") {
    return <>{children}</>;
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <Link href="/" className="brand">
          <span className="brand-mark" aria-hidden="true">
            SF
          </span>
          SignalForge
        </Link>

        <nav className="nav" aria-label="Main">
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="nav-link"
              aria-current={
                item.href === "/"
                  ? pathname === "/"
                    ? "page"
                    : undefined
                  : pathname.startsWith(item.href)
                    ? "page"
                    : undefined
              }
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="sidebar-footer">
          {session && (
            <div className="stack">
              <span className="secondary">{session.user.email}</span>
              <span>
                {session.user.role} · {session.user.tenant}
              </span>
            </div>
          )}
          <div className="row" style={{ gap: 6 }}>
            <button type="button" className="chart-toggle" onClick={toggleTheme}>
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </button>
            <button type="button" className="chart-toggle" onClick={signOut}>
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <main className="main">{children}</main>
    </div>
  );
}
