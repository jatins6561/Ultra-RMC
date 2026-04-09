// backend/server.js

import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";

/* ---------------- ENV ---------------- */
dotenv.config();

/* ---------------- INIT APP ---------------- */
const app = express();

/* ---------------- ROUTES IMPORT ---------------- */
import authRoutes from "./src/routes/auth.routes.js";
import recordsRouter from "./src/routes/records.js";
import adminRouter from "./src/routes/admin.routes.js";

/* ---------------- Middleware ---------------- */
app.use(express.json({ limit: "1mb" }));

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan("dev"));

/* ---------------- CORS ---------------- */
const allowlist = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, _res, next) => {
  if (req.headers.origin && allowlist.length && !allowlist.includes(req.headers.origin)) {
    console.warn("⚠️ CORS blocked for origin:", req.headers.origin);
  }
  next();
});

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (allowlist.length === 0 || allowlist.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for ${origin}`));
    },
    credentials: false,
  })
);

app.options("*", cors());

/* ---------------- Database ---------------- */
const DB_NAME = process.env.DB_NAME || "ultratech_rmc";

mongoose
  .connect(process.env.MONGO_URI, { dbName: DB_NAME })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error", err);
    process.exit(1);
  });

/* ---------------- Health Route ---------------- */
app.get("/", (_req, res) => {
  res.json({ ok: true, service: "ultratech-rmc-backend" });
});

/* ---------------- API ROUTES ---------------- */
app.use("/api/auth", authRoutes);
app.use("/api/records", recordsRouter);
app.use("/api/admin", adminRouter);

/* 🔥 ANALYTICS ROUTES */

/* 🔍 DEBUG ROUTE (VERY USEFUL) */
app.get("/api/debug/routes", (_req, res) => {
  res.json({
    availableRoutes: [
      "/api/auth",
      "/api/records",
      "/api/admin"
    ],
  });
});

/* ---------------- 404 HANDLER ---------------- */
app.use((req, res) => {
  console.warn("❌ Route not found:", req.method, req.originalUrl);
  res.status(404).json({
    error: "Route not found",
    path: req.originalUrl,
  });
});

/* ---------------- Error handler ---------------- */
app.use((err, _req, res, _next) => {
  if (String(err?.message || "").startsWith("CORS blocked")) {
    return res.status(403).json({ error: "CORS not allowed from this origin" });
  }

  console.error("🔥 Unhandled error:", err);

  return res.status(500).json({
    error: "Server error",
    details: err.message,
  });
});

/* ---------------- Server ---------------- */
const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`🚀 API running on http://localhost:${port}`);
  console.log(`📊 Analytics endpoint: http://localhost:${port}/api/analytics/zone`);
});
