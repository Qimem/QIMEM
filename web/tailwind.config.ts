import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "base-bg": "#0B0D10",
        "base-surface": "#121417",
        "base-border": "#3B4148",
        "base-text": "#D0D4D9",
        accent: "#C9D1D9",
        "accent-strong": "#F2F4F6",
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(201,209,217,0.28), 0 0 22px rgba(201,209,217,0.18)",
        glow: "0 0 0 1px rgba(201,209,217,0.35), 0 0 14px rgba(201,209,217,0.2)",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "Inter", "sans-serif"],
        mono: ["var(--font-jetbrains)", "JetBrains Mono", "ui-monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
