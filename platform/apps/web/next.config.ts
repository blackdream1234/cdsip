import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // Allow local network access for development
  allowedDevOrigins: ["http://192.168.1.19:3000", "192.168.1.19", "*"],
};

export default nextConfig;
