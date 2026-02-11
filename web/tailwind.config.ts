import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "base-bg": "#0E1116",
        "base-surface": "#161B22",
        "base-border": "#2A2F36",
        "base-text": "#D4D4D8",
        accent: "#2DD4BF",
      },
      boxShadow: {
        panel: "0 10px 24px rgba(0, 0, 0, 0.35)",
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
