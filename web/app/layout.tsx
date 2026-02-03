import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "QIMEM | Secure Ops",
  description: "Military-grade cryptography console",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
