// backend/src/middleware/auth.js
import jwt from 'jsonwebtoken';

/**
 * Ensure JWT secret exists before verifying tokens.
 * This avoids silent undefined-secret verification.
 */
function ensureJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not set in environment variables');
  }
}

/**
 * Extract token from request:
 * - Authorization: Bearer <token> (any header case)
 * - x-access-token header
 * - cookie named "token" (optional, for future)
 */
function getTokenFromReq(req) {
  // Normalize header name lookup
  const headers = req.headers || {};
  // Common spellings/casing of Authorization
  const authHeader =
    headers.authorization ||
    headers.Authorization ||
    headers.AUTHORIZATION ||
    '';

  if (typeof authHeader === 'string') {
    const val = authHeader.trim();
    if (val.toLowerCase().startsWith('bearer ')) {
      return val.slice(7).trim();
    }
  }

  // Alternate header
  if (headers['x-access-token']) {
    return String(headers['x-access-token']).trim();
  }

  // Optional cookie (if you enable cookie-based auth later)
  if (req.cookies?.token) return req.cookies.token;

  return null;
}

/**
 * JWT authentication middleware.
 * - Verifies token.
 * - Attaches `req.user` = { id, email, role, emailOrId, iat, exp, ... }.
 *   * role is normalized to lowercase
 *   * id falls back to common JWT fields (id | sub | _id)
 *   * emailOrId equals email (if present) otherwise id
 * - Rejects if token missing, expired, or invalid.
 */
export function authRequired(req, res, next) {
  try {
    ensureJwtSecret();

    const token = getTokenFromReq(req);
    if (!token) {
      return res.status(401).json({ error: 'Missing token' });
    }

    // Verify token
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256', 'HS384', 'HS512'], // allowed HMAC variants
      clockTolerance: 5, // seconds of clock drift tolerance
    });

    // Normalize & enrich
    const normalized = { ...payload };
    // Normalize role to lowercase if present
    if (normalized.role) normalized.role = String(normalized.role).toLowerCase();

    // Prefer explicit id, else common JWT fields
    normalized.id = normalized.id || normalized.sub || normalized._id || null;

    // Convenience: emailOrId for downstream filters
    normalized.emailOrId = normalized.email || normalized.id || '';

    req.user = normalized;
    return next();
  } catch (err) {
    const msg =
      err?.name === 'TokenExpiredError'
        ? 'Token expired'
        : err?.name === 'JsonWebTokenError'
        ? 'Invalid token'
        : 'Unauthorized';
    return res.status(401).json({ error: msg });
  }
}

/**
 * Role-based access guard.
 * Usage:
 *   router.get('/admin', authRequired, requireRole('admin'), handler);
 *   router.get('/mgr', authRequired, requireRole('admin','rm','sm'), handler);
 */
export function requireRole(...roles) {
  // Flatten and normalize to lowercase
  const allowed = roles.flat().filter(Boolean).map(r => String(r).toLowerCase());

  return (req, res, next) => {
    const userRole = String(req.user?.role || '').toLowerCase();
    if (!userRole) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (allowed.length > 0 && !allowed.includes(userRole)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };
}
