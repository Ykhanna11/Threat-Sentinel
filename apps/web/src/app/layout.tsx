import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatSentinel | Security intelligence with clarity",
  description:
    "ThreatSentinel is a privacy-first cybersecurity intelligence platform in development by Meta Infinium.",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
