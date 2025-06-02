export default {
  host: process.env.HOST || "127.0.0.1",
  port: parseInt(process.env.PORT || "0") || 31337,
  frontend: process.env.FRONTEND_URL || "http://localhost:3000",
  dev: process.env.NODE_ENV === "development",
};
