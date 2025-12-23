// backend/src/routes/admin.routes.js
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import Team from '../models/Team.js';
import { authRequired, requireRole } from '../middleware/auth.js';

const router = Router();

/* ----------------------------- Helpers ----------------------------- */

/** Keep only whitelisted keys and coerce structure into arrays/strings */
function sanitizeTeam(rawTeam) {
  if (!Array.isArray(rawTeam)) return [];

  const cleanString = (v) =>
    (typeof v === 'string' ? v : '')
      .toString()
      .slice(0, 120)
      .trim();

  const sanitizeUsers = (users) => {
    if (!Array.isArray(users)) users = [];
    // keep only first user (your UI uses one)
    const u0 = users[0] || {};
    const userId = cleanString(u0.userId || ''); // trimmed
    const password = typeof u0.password === 'string' ? u0.password : undefined;
    const passwordHash = typeof u0.passwordHash === 'string' ? u0.passwordHash : undefined;
    const out = { userId };
    if (password) out.password = password;
    if (passwordHash) out.passwordHash = passwordHash;
    return [out];
  };

  const sanitizeSE = (se) => ({
    name: cleanString(se?.name || ''),
    users: sanitizeUsers(se?.users),
  });

  const sanitizeSM = (sm) => ({
    name: cleanString(sm?.name || ''),
    users: sanitizeUsers(sm?.users),
    ses: Array.isArray(sm?.ses) ? sm.ses.slice(0, 100).map(sanitizeSE) : [],
  });

  const sanitizeRM = (rm) => ({
    name: cleanString(rm?.name || ''),
    users: sanitizeUsers(rm?.users),
    sms: Array.isArray(rm?.sms) ? rm.sms.slice(0, 100).map(sanitizeSM) : [],
  });

  const sanitizeZone = (z) => ({
    name: cleanString(z?.name || ''),
    users: sanitizeUsers(z?.users),
    rms: Array.isArray(z?.rms) ? z.rms.slice(0, 100).map(sanitizeRM) : [],
  });

  // Cap counts at each level to prevent abuse
  return rawTeam.slice(0, 100).map(sanitizeZone);
}

/** Hash any plaintext `password` fields into `passwordHash`, remove `password` */
async function hashTeamPasswords(team) {
  const maybeHash = async (user) => {
    if (user && typeof user.password === 'string' && user.password.length > 0) {
      user.passwordHash = await bcrypt.hash(user.password, 10);
      delete user.password;
    }
  };

  const walkSE = async (se) => { if (se?.users) await Promise.all(se.users.map(maybeHash)); };
  const walkSM = async (sm) => {
    if (sm?.users) await Promise.all(sm.users.map(maybeHash));
    if (Array.isArray(sm?.ses)) for (const se of sm.ses) await walkSE(se);
  };
  const walkRM = async (rm) => {
    if (rm?.users) await Promise.all(rm.users.map(maybeHash));
    if (Array.isArray(rm?.sms)) for (const sm of rm.sms) await walkSM(sm);
  };
  const walkZone = async (z) => {
    if (z?.users) await Promise.all(z.users.map(maybeHash));
    if (Array.isArray(z?.rms)) for (const rm of z.rms) await walkRM(rm);
  };

  if (Array.isArray(team)) {
    for (const z of team) await walkZone(z);
  }
}

/** small helpers used across routes */
const cleanStr = (v) => (typeof v === 'string' ? v : '').trim();

/** Check if a node (zone/rm/sm/se) contains a user with given userId */
function matchUserAt(node, userId) {
  const want = cleanStr(userId);
  return Array.isArray(node?.users) && node.users.some(u => cleanStr(u.userId) === want);
}

/** Return the subtree visible to a user (by role + emailOrId/userId) */
function extractSubtreeForUser(teamDoc, role, emailOrId) {
  if (!teamDoc) return null;
  const zones = teamDoc.team || [];
  const r = (role || '').toLowerCase();

  if (r === 'admin') {
    return { scope: 'admin', root: zones }; // full tree
  }

  for (const zone of zones) {
    if (r === 'zone' && matchUserAt(zone, emailOrId)) {
      return { scope: 'zone', root: zone };
    }
    for (const rm of (zone.rms || [])) {
      if (r === 'rm' && matchUserAt(rm, emailOrId)) {
        return { scope: 'rm', root: rm };
      }
      for (const sm of (rm.sms || [])) {
        if (r === 'sm' && matchUserAt(sm, emailOrId)) {
          return { scope: 'sm', root: sm };
        }
        for (const se of (sm.ses || [])) {
          if (r === 'se' && matchUserAt(se, emailOrId)) {
            return { scope: 'se', root: se };
          }
        }
      }
    }
  }
  return null;
}

/** Infer functional role (zone|rm|sm|se) by scanning the Team tree */
function inferFunctionalRole(teamDoc, emailOrId){
  const id = cleanStr(emailOrId);
  if (!teamDoc || !id) return null;

  const zones = Array.isArray(teamDoc.team) ? teamDoc.team : [];
  const hasUser = (node) => Array.isArray(node?.users) && node.users.some(u => cleanStr(u.userId) === id);

  for (const zone of zones){
    if (hasUser(zone)) return 'zone';
    for (const rm of (zone.rms || [])){
      if (hasUser(rm)) return 'rm';
      for (const sm of (rm.sms || [])){
        if (hasUser(sm)) return 'sm';
        for (const se of (sm.ses || [])){
          if (hasUser(se)) return 'se';
        }
      }
    }
  }
  return null;
}

/* ----------------------------- Routes ----------------------------- */

/** Admin: Get entire team they own */
router.get(
  '/team',
  authRequired,
  requireRole('admin'),
  async (req, res) => {
    const existing = await Team.findOne({ ownerUserId: req.user.id }).lean();
    if (!existing) return res.json({ team: [] });
    return res.json({ team: existing.team, updatedAt: existing.updatedAt });
  }
);

/** Admin: Save/replace entire team */
router.post(
  '/team',
  authRequired,
  requireRole('admin'),
  async (req, res) => {
    try {
      const incoming = Array.isArray(req.body?.team) ? req.body.team : [];
      const team = sanitizeTeam(incoming);
      await hashTeamPasswords(team);

      const saved = await Team.findOneAndUpdate(
        { ownerUserId: req.user.id },
        { $set: { team } },
        { upsert: true, new: true }
      );

      return res.status(201).json({ ok: true, team: saved.team });
    } catch (err) {
      console.error('team save error:', err);
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

/**
 * Everyone authenticated: get the subtree relevant to the logged-in user.
 * - admin => full tree (under their ownerUserId)
 * - zone  => that Zone node
 * - rm    => that RM node
 * - sm    => that SM node
 * - se    => that SE node
 */
router.get(
  '/my-team',
  authRequired,
  async (req, res) => {
    try {
      const role = (req.user.role || '').toLowerCase();
      let teamDoc = null;

      if (role === 'admin') {
        teamDoc = await Team.findOne({ ownerUserId: req.user.id }).lean();
        // If you support multiple admins and a user could be linked to a specific admin,
        // scope to that admin here.
      } else {
        // Assuming single-team deployment; otherwise store which admin this user belongs to.
        teamDoc = await Team.findOne({}).lean();
      }

      if (!teamDoc) return res.json({ scope: role, root: null });

      const emailOrId = req.user.email || req.user.emailOrId || '';
      const subtree = extractSubtreeForUser(teamDoc, role, emailOrId);
      return res.json(subtree || { scope: role, root: null });
    } catch (err) {
      console.error('my-team error:', err);
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

/* ---------------------- NEW: role resolver ------------------------ */
/**
 * GET /api/admin/whoami-role
 * Returns { role: 'admin' | 'zone' | 'rm' | 'sm' | 'se' | 'user' }
 * - admin stays 'admin' (from JWT)
 * - others inferred from Team (fallback 'user' if not found)
 */
router.get('/whoami-role', authRequired, async (req, res) => {
  try{
    const baseRole = (req.user.role || '').toLowerCase();
    if (baseRole === 'admin') {
      return res.json({ role: 'admin' });
    }

    // For non-admins, infer from the (single) Team doc.
    // If you have multi-tenancy per admin, adjust this query appropriately.
    const teamDoc = await Team.findOne({}).lean();
    if (!teamDoc) return res.json({ role: 'user' });

    const emailOrId = req.user.email || req.user.emailOrId || '';
    const functional = inferFunctionalRole(teamDoc, emailOrId);
    return res.json({ role: functional || 'user' });
  }catch(err){
    console.error('whoami-role error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
