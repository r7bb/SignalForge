import type { Metadata } from "next";
import type { ReactNode } from "react";

import { Shell } from "@/components/Shell";

import "./globals.css";

export const metadata: Metadata = {
  title: "SignalForge",
  description:
    "Cloud-native detection & response: OCSF normalization, Sigma detections, behavioural correlation and incident case management.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
