import type { NextConfig } from "next";

const backend = new URL(
  `http://localhost:${process.env.NEXT_PUBLIC_BACKEND || "31337"}`,
);

const nextConfig: NextConfig = {
  trailingSlash: true,
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${backend}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
