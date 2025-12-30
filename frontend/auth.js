// ------------------------------
// Shared Auth Helper for Frontend
// ------------------------------

// 🔥 SINGLE SOURCE OF TRUTH FOR BACKEND URL
const API_BASE =
  (location.hostname === '127.0.0.1' || location.hostname === 'localhost')
    ? 'http://localhost:10000'
    : 'https://ultra-rmc-1.onrender.com';

// ------------------------------
// Authentication helper
// ------------------------------
const AUTH = {
  get token() {
    return localStorage.getItem('token') || '';
  },
  set token(v) {
    localStorage.setItem('token', v);
  },

  get user() {
    try {
      return JSON.parse(localStorage.getItem('user') || 'null');
    } catch {
      return null;
    }
  },
  set user(u) {
    localStorage.setItem('user', JSON.stringify(u));
  },

  clear() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },
};

// ------------------------------
// Auth guard
// ------------------------------
function requireAuth() {
  if (!AUTH.token) {
    sessionStorage.setItem('redirectAfterLogin', location.pathname);
    location.href = 'login.html';
  }
}

// ------------------------------
// Logout helper
// ------------------------------
function logout() {
  AUTH.clear();
  location.href = 'login.html';
}

// ------------------------------
// Authorized fetch wrapper
// ------------------------------
async function apiFetch(url, options = {}) {
  const headers = options.headers || {};

  if (AUTH.token) {
    headers['Authorization'] = `Bearer ${AUTH.token}`;
  }

  headers['Content-Type'] = 'application/json';

  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }

  return res.json();
}

console.log('✅ Auth helpers loaded');
console.log('🌍 API_BASE =', API_BASE);
