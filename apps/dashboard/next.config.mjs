/** @type {import('next').NextConfig} */
const apiBase = process.env.SIGNALFORGE_API_BASE ?? "http://localhost:8000";

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: "standalone",
  async rewrites() {
    // The browser talks to /api/* on the dashboard's own origin; Next proxies
    // to the FastAPI service, so there is no CORS story in production.
    return [
      { source: "/api/:path*", destination: `${apiBase}/api/:path*` },
      { source: "/openapi.json", destination: `${apiBase}/openapi.json` },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
};

export default nextConfig;
