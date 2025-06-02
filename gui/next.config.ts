import type { NextConfig } from "next";

const backend = new URL(process.env.BACKEND || "http://127.0.0.1:31337");

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${backend}api/:path*`,
      },
    ];
  },
};

export default nextConfig;
