import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter var", "Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        ink: {
          950: "#09090b",
          900: "#111113",
          800: "#18181b",
          700: "#1f1f23",
          600: "#27272a",
          500: "#71717a",
          400: "#71717a",
          300: "#a1a1aa",
          200: "#d4d4d8",
          100: "#e4e4e7",
          50: "#fafafa",
        },
        accent: {
          DEFAULT: "#2dd4bf",
          hover: "#5eead4",
          muted: "#0d3d37",
        },
        severity: {
          public: "#f87171",
          publicWrite: "#ef4444",
          protected: "#a1a1aa",
          notFound: "#52525b",
          locked: "#fbbf24",
          rateLimited: "#f59e0b",
          error: "#f97316",
          unknown: "#6b7280",
          appCheck: "#a78bfa",
        },
      },
      boxShadow: {
        "inset-border": "inset 0 0 0 1px rgba(255,255,255,0.06)",
      },
      keyframes: {
        shimmer: {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(400%)" },
        },
      },
      animation: {
        shimmer: "shimmer 1.4s linear infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;
