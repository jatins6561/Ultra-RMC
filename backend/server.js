// backend/server.js
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import morgan from 'morgan';

// ROUTES (all under src/)
import authRoutes from './src/routes/auth.routes.js';
import recordsRouter from './src/routes/records.js';
import adminRouter from './src/routes/admin.routes.js';

dotenv.config();

const app = express();

/* ---------------- Middleware ---------------- */
app.use(express.json({ limit: '1mb' }));

// Helmet: don’t enforce CORP for an API (it can block cross-origin fetches)
app.use(helmet({ crossOriginResourcePolicy: false }));

// Request log (dev friendly)
app.use(morgan('dev'));

// CORS allowlist from .env (comma-separated origins)
const allowlist = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Small logger to surface blocked origins during dev
app.use((req, _res, next) => {
  if (req.headers.origin && allowlist.length && !allowlist.includes(req.headers.origin)) {
    console.warn('CORS blocked for origin:', req.headers.origin);
  }
  next();
});

app.use(
  cors({
    origin(origin, cb) {
      // allow tools/curl/Postman (no Origin header)
      if (!origin) return cb(null, true);
      if (allowlist.length === 0 || allowlist.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for ${origin}`));
    },
    credentials: false,
  })
);

// Ensure OPTIONS preflight succeeds for all routes
app.options('*', cors());

/* ---------------- Database ---------------- */
const DB_NAME = process.env.DB_NAME || 'ultratech_rmc';

mongoose
  .connect(process.env.MONGO_URI, { dbName: DB_NAME })
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('❌ MongoDB error', err);
    process.exit(1);
  });

/* ---------------- Routes ---------------- */
app.get('/', (_req, res) => {
  res.json({ ok: true, service: 'ultratech-rmc-backend' });
});

app.use('/api/auth', authRoutes);
app.use('/api/records', recordsRouter);
app.use('/api/admin', adminRouter);

/* ---------------- Error handler (CORS / others) ---------------- */
app.use((err, _req, res, _next) => {
  if (String(err?.message || '').startsWith('CORS blocked')) {
    return res.status(403).json({ error: 'CORS not allowed from this origin' });
  }
  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Server error' });
});

/* ---------------- Server ---------------- */
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`🚀 API on http://localhost:${port}`));
