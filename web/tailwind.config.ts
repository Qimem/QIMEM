import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"] ,
  theme: {
    extend: {
      colors: {
        base: {
          900: "#0E1116",
          800: "#161B22",
          700: "#1F252E",
          600: "#2A2F36",
        },
        accent: {
          DEFAULT: "#2DD4BF",
          green: "#22C55E",
        },
      },
      boxShadow: {
        panel: "0 10px 30px rgba(0, 0, 0, 0.35)",
      },
      borderRadius: {
        md: "6px",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "Inter", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "JetBrains Mono", "ui-monospace", "SFMono-Regular"],
      },
    },
  },
  plugins: [],
};

export default config;
