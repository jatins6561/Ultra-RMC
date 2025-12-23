// backend/src/routes/auth.routes.js
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import Team from '../models/Team.js';
import { authRequired } from '../middleware/auth.js';

const router = Router();

/* ------------------------------ Helpers ------------------------------ */

const ensureJwtSecret = () => {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET not set in environment');
};

function signToken(payload) {
  ensureJwtSecret();
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function ciEq(a = '', b = '') {
  return String(a).toLowerCase().trim() === String(b).toLowerCase().trim();
}

/**
 * Search all Team documents for a matching userId + passwordHash
 * Returns a { id, email, role } object if matched; else null
 */
async function findTeamLogin(emailOrId, plainPassword) {
  const teams = await Team.find({}).lean();
  for (const t of teams) {
    const matchUser = async (user, role) => {
      if (!user?.userId || !user?.passwordHash) return null;
      if (!ciEq(user.userId, emailOrId)) return null;
      const ok = await bcrypt.compare(plainPassword, user.passwordHash);
      if (!ok) return null;
      // Use a synthetic id namespaced to the team doc
      return { id: `team:${t._id.toString()}`, email: user.userId, role };
    };

    const zones = t.team || [];
    for (const z of zones) {
      if (z?.users?.[0]) {
        const ok = await matchUser(z.users[0], 'zone');
        if (ok) return ok;
      }
      for (const rm of (z?.rms || [])) {
        if (rm?.users?.[0]) {
          const ok = await matchUser(rm.users[0], 'rm');
          if (ok) return ok;
        }
        for (const sm of (rm?.sms || [])) {
          if (sm?.users?.[0]) {
            const ok = await matchUser(sm.users[0], 'sm');
            if (ok) return ok;
          }
          for (const se of (sm?.ses || [])) {
            if (se?.users?.[0]) {
              const ok = await matchUser(se.users[0], 'se');
              if (ok) return ok;
            }
          }
        }
      }
    }
  }
  return null;
}

/* -------------------------- Auth Endpoints -------------------------- */

// (Optional) quick seed user if none exists
router.post('/seed-admin', async (req, res) => {
  try {
    const { name = 'Admin', email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const exists = await User.findOne({ email });
    if (exists) return res.json({ ok: true, message: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash, role: 'admin' });
    return res.json({ ok: true, id: user._id });
  } catch (err) {
    console.error('seed-admin error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Register regular app user (non-team)
router.post('/register', async (req, res) => {
  try {
    const { name = '', email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'Email already in use' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash, role: 'user' });
    return res.status(201).json({ ok: true, id: user._id });
  } catch (err) {
    console.error('register error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login -> JWT (supports admin/user and team roles zone/rm/sm/se)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    // 1) Try User collection (admin/regular)
    const user = await User.findOne({ email });
    if (user) {
      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

      const token = signToken({ id: user._id.toString(), email: user.email, role: user.role || 'user' });
      return res.json({
        token,
        user: { id: user._id, name: user.name, email: user.email, role: user.role || 'user' },
      });
    }

    // 2) Else try Team nested credentials
    const teamLogin = await findTeamLogin(email, password);
    if (!teamLogin) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken(teamLogin);
    return res.json({
      token,
      user: { id: teamLogin.id, name: teamLogin.email, email: teamLogin.email, role: teamLogin.role },
    });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Me
router.get('/me', authRequired, async (req, res) => {
  try {
    // For team logins (id starts with "team:"), we just echo token info
    if (String(req.user.id || '').startsWith('team:')) {
      return res.json({ user: { id: req.user.id, email: req.user.email, role: req.user.role } });
    }
    const user = await User.findById(req.user.id).select('_id name email role createdAt');
    if (!user) return res.status(404).json({ error: 'Not found' });
    return res.json({ user });
  } catch (err) {
    console.error('me error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Update admin email/password (used by admin-admin.html)
router.post('/update-admin', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const { email, password } = req.body || {};
    const update = {};
    if (email) update.email = email;
    if (typeof password === 'string' && password.length > 0) {
      update.passwordHash = await bcrypt.hash(password, 10);
    }
    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: 'Nothing to update' });
    }
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: update },
      { new: true, select: '_id name email role' }
    );
    return res.json({ ok: true, user });
  } catch (err) {
    console.error('update-admin error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
