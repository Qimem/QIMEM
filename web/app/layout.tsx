import "./globals.css";
import type { ReactNode } from "react";
import { Inter, JetBrains_Mono } from "next/font/google";

export const metadata = {
  title: "QIMEM Playground",
  description: "Tenant-scoped cryptography control plane",
};

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-inter",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-jetbrains",
});

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className={`${inter.variable} ${jetbrains.variable}`}>{children}</body>
    </html>
  );
}
