/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  env: {
    NEXT_PUBLIC_QIMEM_API_BASE_URL: process.env.NEXT_PUBLIC_QIMEM_API_BASE_URL,
  },
  async rewrites() {
    if (!process.env.NEXT_PUBLIC_QIMEM_API_BASE_URL) return [];
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_QIMEM_API_BASE_URL}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
