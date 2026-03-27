import type { NextConfig } from "next";

const config: NextConfig = {
  output: "export",
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
  images: { unoptimized: true },
  webpack(config) {
    config.module.rules.push(
      { test: /\.yaml$/, type: "asset/source" },
      { test: /\.md$/, type: "asset/source" },
    );
    return config;
  },
  turbopack: {
    rules: {
      "*.yaml": { loaders: ["raw-loader"], as: "*.js" },
      "*.md": { loaders: ["raw-loader"], as: "*.js" },
    },
  },
};

export default config;
