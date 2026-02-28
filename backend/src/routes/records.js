// backend/src/routes/records.js
import { Router } from 'express';
import Record from '../models/Record.js';
import Team from '../models/Team.js';
import { authRequired } from '../middleware/auth.js';

const router = Router();

/* ----------------------------- helpers ----------------------------- */

function roleToDesignation(role) {
  switch ((role || '').toLowerCase()) {
    case 'zone': return 'Zonal Head';
    case 'rm':   return 'Regional Manager';
    case 'sm':   return 'Sales Manager';
    case 'se':   return 'Sales Executive';
    case 'admin':return 'Admin';
    default:     return 'User';
  }
}

function deriveName(emailOrId = '') {
  const s = String(emailOrId).trim();
  if (!s) return '';
  if (s.includes('@')) return s.split('@')[0]; // local-part of email
  return s.split(/[^\w]+/)[0];                  // first token
}

const toNum = (v) => {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : 0;
};

function sanitizeMaterials(arr) {
  if (!Array.isArray(arr)) return [];
  return arr
    .filter((m) => m && String(m.name || '').trim().length > 0)
    .map((m) => ({
      name: String(m.name).trim(),
      rate: toNum(m.rate),
      mix:  toNum(m.mix),
      cost: toNum(m.cost),
    }));
}

function sanitizeTM(tm = {}) {
  return {
    L1: toNum(tm.L1), L2: toNum(tm.L2), L3: toNum(tm.L3),
    L4: toNum(tm.L4), L5: toNum(tm.L5), L6: toNum(tm.L6),
    L7: toNum(tm.L7), L8: toNum(tm.L8), L9: toNum(tm.L9),
  };
}

function sanitizePricing(p = {}) {
  return {
    C1: toNum(p.C1),  C2: toNum(p.C2),  C3: toNum(p.C3),  C4: toNum(p.C4),
    C5: toNum(p.C5),  C6: toNum(p.C6),  C7: toNum(p.C7),  C8: toNum(p.C8),
    C9: toNum(p.C9),  C10: toNum(p.C10), C11: toNum(p.C11), C12: toNum(p.C12),
    C13: toNum(p.C13), C14: toNum(p.C14), C15: toNum(p.C15), C16: toNum(p.C16),
    C17: toNum(p.C17),
  };
}

/* ---- helpers for team scoping (Team Records) ---- */

const safeStr = (v) => (typeof v === 'string' ? v : '').trim();

function matchUserAt(node, emailOrId) {
  const target = safeStr(emailOrId);
  if (!target) return false;
  const users = Array.isArray(node?.users) ? node.users : [];
  return users.some(u => safeStr(u.userId) === target);
}

// Find the subtree visible to the logged-in user by role + emailOrId
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

// Collect team userIds at the requested target level within a subtree
function collectIdsByTarget(root, target /* 'rm'|'sm'|'se' */) {
  const ids = [];

  const pushIf = (node) => {
    const u = Array.isArray(node?.users) ? node.users[0] : null;
    const id = safeStr(u?.userId);
    if (id) ids.push(id);
  };

  if (!root) return ids;

  if (Array.isArray(root)) {
    // admin full tree passed as array of zones
    for (const z of root) {
      if (target === 'rm') {
        for (const rm of (z.rms || [])) pushIf(rm);
      } else if (target === 'sm') {
        for (const rm of (z.rms || [])) for (const sm of (rm.sms || [])) pushIf(sm);
      } else if (target === 'se') {
        for (const rm of (z.rms || [])) for (const sm of (rm.sms || [])) for (const se of (sm.ses || [])) pushIf(se);
      }
    }
    return ids;
  }

  // single node subtree (zone / rm / sm / se)
  if (target === 'rm') {
    for (const rm of (root.rms || [])) pushIf(rm);
  } else if (target === 'sm') {
    if (Array.isArray(root.sms)) {
      for (const sm of root.sms) pushIf(sm);
    } else if (Array.isArray(root.rms)) {
      for (const rm of root.rms) for (const sm of (rm.sms || [])) pushIf(sm);
    } else {
      pushIf(root);
    }
  } else if (target === 'se') {
    if (Array.isArray(root.ses)) {
      for (const se of root.ses) pushIf(se);
    } else if (Array.isArray(root.sms)) {
      for (const sm of root.sms) for (const se of (sm.ses || [])) pushIf(se);
    } else if (Array.isArray(root.rms)) {
      for (const rm of root.rms) for (const sm of (rm.sms || [])) for (const se of (sm.ses || [])) pushIf(se);
    } else {
      pushIf(root);
    }
  }

  return ids;
}

/* ------------------------------ create ----------------------------- */
/**
 * POST /api/records
 * Body: full calculator payload + optional { status: 'draft' | 'submitted' }
 * Captures createdBy from JWT. Returns { ok, p_id, status }.
 */
router.post('/', authRequired, async (req, res) => {
  try {
    const payload = req.body || {};
    const status = (String(payload.status || 'draft').toLowerCase() === 'submitted')
      ? 'submitted'
      : 'draft';

    const createdBy = {
      userId: req.user.id,
      emailOrId: req.user.email || '',
      role: req.user.role || 'user',
      designation: roleToDesignation(req.user.role),
      name: deriveName(req.user.email || req.user.id || ''),
    };

    const record = await Record.create({
      date: payload.date ? new Date(payload.date) : undefined,

      project: String(payload.project || ''),
      qty: toNum(payload.qty),
      grade: String(payload.grade || ''),
      plant: String(payload.plant || ''),
      site: String(payload.site || ''),
      grade_record: String(payload.grade_record || ''),
      mix_version: String(payload.mix_version || ''),

      pump: { P1: toNum(payload?.pump?.P1) },

      tm: sanitizeTM(payload.tm || {}),
      pricing: sanitizePricing(payload.pricing || {}),
      materials: sanitizeMaterials(payload.materials),

      status,
      createdBy,
    });

    return res.status(201).json({ ok: true, p_id: record._id, status: record.status });
  } catch (err) {
    console.error('record create error:', err);
    return res.status(400).json({
      error: 'Invalid payload',
      details: err?.message || String(err),
    });
  }
});

/* -------------------------------- list ----------------------------- */
/**
 * GET /api/records?status=draft|submitted&from=YYYY-MM-DD&to=YYYY-MM-DD
 * Optional creator filters:
 *   createdByRole=se|sm|rm|zone|admin
 *   createdById=<emailOrId>
 */
router.get('/', authRequired, async (req, res) => {
  try {
    const { status, from, to, createdByRole, createdById } = req.query;

  const q = {};

// 🔒 Restrict non-admin users to their own records
if (req.user.role !== 'admin') {
  q['createdBy.userId'] = req.user.id;
}
    if (status && ['draft', 'submitted'].includes(String(status).toLowerCase())) {
      q.status = String(status).toLowerCase();
    }
    if (from || to) {
      q.date = {};
      if (from) q.date.$gte = new Date(from);
      if (to)   q.date.$lte = new Date(to + 'T23:59:59.999Z');
    }
    if (createdByRole) {
      q['createdBy.role'] = String(createdByRole).toLowerCase();
    }
    if (createdById) {
      q['createdBy.emailOrId'] = String(createdById).trim();
    }

    const rows = await Record.find(q).sort({ createdAt: -1 }).lean();
    return res.json({ rows });
  } catch (err) {
    console.error('records list error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------ team records (scoped) -------------------- */
/**
 * GET /api/records/team
 * Query params:
 *   target=rm|sm|se
 *   status= draft|submitted (optional)
 *   from=YYYY-MM-DD, to=YYYY-MM-DD (optional)
 */
router.get('/team', authRequired, async (req, res) => {
  try {
    const role = (req.user.role || '').toLowerCase();
    const target = (req.query.target || '').toLowerCase(); // rm | sm | se
    const { status, from, to } = req.query;

    if (!['rm', 'sm', 'se'].includes(target)) {
      return res.status(400).json({ error: 'target must be one of rm|sm|se' });
    }

    let teamDoc = null;
    if (role === 'admin') {
      teamDoc = await Team.findOne({ ownerUserId: req.user.id }).lean();
      if (!teamDoc) teamDoc = await Team.findOne({}).lean();
    } else {
      teamDoc = await Team.findOne({}).lean();
    }

    if (!teamDoc) return res.json({ rows: [] });

    const emailOrId = req.user.email || req.user.emailOrId || '';
    const subtree = extractSubtreeForUser(teamDoc, role, emailOrId) || { root: null };
    const ids = collectIdsByTarget(subtree.root ?? [], target);
    if (ids.length === 0) return res.json({ rows: [] });

    const q = {
      'createdBy.role': target,
      'createdBy.emailOrId': { $in: ids },
    };

    if (status && ['draft', 'submitted'].includes(String(status).toLowerCase())) {
      q.status = String(status).toLowerCase();
    }
    if (from || to) {
      q.date = {};
      if (from) q.date.$gte = new Date(from);
      if (to)   q.date.$lte = new Date(to + 'T23:59:59.999Z');
    }

    const rows = await Record.find(q).sort({ createdAt: -1 }).lean();
    return res.json({ rows, ids });
  } catch (err) {
    console.error('team records error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* --------- BACK-COMPAT: /api/records/by/team (role + userId) ------ */
/**
 * GET /api/records/by/team
 * Query params:
 *   role=rm|sm|se
 *   userId=<team user id string>
 *   status=draft|submitted (optional)
 *   from=YYYY-MM-DD, to=YYYY-MM-DD (optional)
 *
 * This serves existing pages that still call /by/team.
 */
router.get('/by/team', authRequired, async (req, res) => {
  try {
    const role = String(req.query.role || '').toLowerCase();   // rm|sm|se
    const userId = safeStr(req.query.userId || '');
    const { status, from, to } = req.query;

    if (!['rm', 'sm', 'se'].includes(role) || !userId) {
      return res.status(400).json({ error: 'role (rm|sm|se) and userId are required' });
    }

    const q = {
      'createdBy.role': role,
      'createdBy.emailOrId': userId,
    };
    if (status && ['draft', 'submitted'].includes(String(status).toLowerCase())) {
      q.status = String(status).toLowerCase();
    }
    if (from || to) {
      q.date = {};
      if (from) q.date.$gte = new Date(from);
      if (to)   q.date.$lte = new Date(to + 'T23:59:59.999Z');
    }

    const rows = await Record.find(q).sort({ createdAt: -1 }).lean();
    return res.json({ rows });
  } catch (err) {
    console.error('team by/member error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------------ get one --------------------------- */
/**
 * GET /api/records/:id
 * Fetch one record by Mongo _id
 */
router.get('/:id', authRequired, async (req, res) => {
  try {
    const doc = await Record.findById(req.params.id).lean();
    if (!doc) return res.status(404).json({ error: 'Not found' });
    return res.json(doc);
  } catch (err) {
    console.error('record fetch error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------------ update ---------------------------- */
router.patch('/:id', authRequired, async (req, res) => {
  try {
    const id = req.params.id;
    const src = { ...(req.body || {}) };

    delete src.createdBy;

    const payload = {
      ...(src.date !== undefined ? { date: new Date(src.date) } : {}),
      ...(src.project !== undefined ? { project: String(src.project || '') } : {}),
      ...(src.qty !== undefined ? { qty: toNum(src.qty) } : {}),
      ...(src.grade !== undefined ? { grade: String(src.grade || '') } : {}),
      ...(src.plant !== undefined ? { plant: String(src.plant || '') } : {}),
      ...(src.site !== undefined ? { site: String(src.site || '') } : {}),
      ...(src.grade_record !== undefined ? { grade_record: String(src.grade_record || '') } : {}),
      ...(src.mix_version !== undefined ? { mix_version: String(src.mix_version || '') } : {}),
      ...(src.pump !== undefined ? { pump: { P1: toNum(src?.pump?.P1) } } : {}),
      ...(src.tm !== undefined ? { tm: sanitizeTM(src.tm) } : {}),
      ...(src.pricing !== undefined ? { pricing: sanitizePricing(src.pricing) } : {}),
      ...(src.materials !== undefined ? { materials: sanitizeMaterials(src.materials) } : {}),
    };

    if (src.status && ['draft', 'submitted'].includes(String(src.status).toLowerCase())) {
      payload.status = String(src.status).toLowerCase();
    }

    const rec = await Record.findByIdAndUpdate(id, { $set: payload }, { new: true });
    if (!rec) return res.status(404).json({ error: 'Not found' });

    return res.json({ ok: true });
  } catch (err) {
    console.error('record update error:', err);
    return res.status(400).json({ error: 'Invalid payload', details: err?.message || String(err) });
  }
});

/* ------------------------------ delete ---------------------------- */
router.delete('/:id', authRequired, async (req, res) => {
  try {
    const id = req.params.id;
    const out = await Record.findByIdAndDelete(id);
    if (!out) return res.status(404).json({ error: 'Not found' });
    return res.json({ ok: true });
  } catch (err) {
    console.error('record delete error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------------ submit ---------------------------- */
router.patch('/:id/submit', authRequired, async (req, res) => {
  try {
    const id = req.params.id;
    const rec = await Record.findByIdAndUpdate(
      id,
      { $set: { status: 'submitted' } },
      { new: true }
    );
    if (!rec) return res.status(404).json({ error: 'Not found' });
    return res.json({ ok: true, status: rec.status });
  } catch (err) {
    console.error('record submit error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/team/matrix', authRequired, async (req,res)=>{
try{

 if(req.user.role!=='zone'){
   return res.status(403).json({error:'Only Zone'});
 }

 const {from,to}=req.query;

 const match={
   status:'submitted'
 };

 if(from||to){
   match.createdAt={};
   if(from) match.createdAt.$gte=new Date(from);
   if(to) match.createdAt.$lte=new Date(to+'T23:59:59.999Z');
 }

 // count per user (any role)
 const recs=await Record.find(match).lean();
 const counter={};

 recs.forEach(r=>{
   const id=r.createdBy.emailOrId;
   if(!id) return;
   counter[id]=(counter[id]||0)+1;
 });

 const team=await Team.findOne({}).lean();
 const rows=[];

 for(const z of team.team||[]){
   for(const rm of z.rms||[]){
     const rmu=rm.users?.[0];

     const rmEmail=rmu?.userId||'';
     rows.push({
       role:'rm',
       label:`${z.name} / ${rm.name} : ${rmEmail}`,
       count:counter[rmEmail]||0
     });

     for(const sm of rm.sms||[]){
       const smu=sm.users?.[0];
       const smEmail=smu?.userId||'';

       rows.push({
         role:'sm',
         label:`${z.name} / ${rm.name} / ${sm.name} : ${smEmail}`,
         count:counter[smEmail]||0
       });

       for(const se of sm.ses||[]){
         const seu=se.users?.[0];
         const seEmail=seu?.userId||'';

         rows.push({
           role:'se',
           label:`${z.name} / ${rm.name} / ${sm.name} / ${se.name} : ${seEmail}`,
           count:counter[seEmail]||0
         });
       }
     }
   }
 }

 res.json({rows});

}catch(e){
 console.error(e);
 res.status(500).json({error:'Server'});
}
});

export default router;

