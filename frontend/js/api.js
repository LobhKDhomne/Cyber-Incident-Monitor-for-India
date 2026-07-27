/**
 * CIMI API client - shared fetch wrapper used across all pages.
 * Include this before any page-specific script:
 *   <script src="../js/api.js"></script>  (from pages/)
 *   <script src="js/api.js"></script>     (from index.html)
 */
(function (global) {
  const API_BASE_URL = window.CIMI_API_BASE_URL || 'http://localhost:4000/api';
  const TOKEN_KEY = 'cimi_token';
  const USER_KEY = 'cimi_user';

  function getToken() {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  function setSession(token, user) {
    sessionStorage.setItem(TOKEN_KEY, token);
    sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
  }

  function getUser() {
    try {
      return JSON.parse(sessionStorage.getItem(USER_KEY) || 'null');
    } catch (_) {
      return null;
    }
  }

  function isAuthenticated() {
    return !!getToken();
  }

  /**
   * Core request helper. Automatically attaches the bearer token and
   * JSON-encodes plain object bodies. Pass a FormData body untouched.
   */
  async function request(path, { method = 'GET', body, headers = {}, auth = true } = {}) {
    const finalHeaders = { ...headers };
    let finalBody = body;

    if (body && !(body instanceof FormData)) {
      finalHeaders['Content-Type'] = 'application/json';
      finalBody = JSON.stringify(body);
    }

    if (auth) {
      const token = getToken();
      if (token) finalHeaders['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${API_BASE_URL}${path}`, { method, headers: finalHeaders, body: finalBody });

    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      /* empty or non-JSON response */
    }

    if (!res.ok) {
      const message = (data && data.error) || `Request failed (${res.status})`;
      if (res.status === 401 && auth) {
        clearSession();
      }
      throw new Error(message);
    }

    return data;
  }

  const CimiAPI = {
    baseUrl: API_BASE_URL,
    getToken,
    getUser,
    isAuthenticated,
    clearSession,

    auth: {
      login: (email, password) => request('/auth/login', { method: 'POST', body: { email, password }, auth: false })
        .then((data) => {
          setSession(data.token, data.user);
          return data;
        }),
      me: () => request('/auth/me'),
      logout: () => request('/auth/logout', { method: 'POST' }).finally(clearSession),
    },

    ioc: {
      lookup: (indicator) => request('/ioc/lookup', { method: 'POST', body: { indicator } }),
      bulk: (indicators) => request('/ioc/bulk', { method: 'POST', body: { indicators } }),
      history: (limit = 50) => request(`/ioc/history?limit=${limit}`),
    },

    dashboard: {
      summary: () => request('/dashboard/summary'),
      trends: (days = 7) => request(`/dashboard/trends?days=${days}`),
      geoDistribution: () => request('/dashboard/geo-distribution'),
    },

    feeds: {
      all: () => request('/feeds'),
      cisaKev: (params = {}) => {
        const qs = new URLSearchParams(params).toString();
        return request(`/feeds/cisa-kev${qs ? `?${qs}` : ''}`);
      },
      otxPulses: (limit = 20) => request(`/feeds/otx-pulses?limit=${limit}`),
    },

    correlation: {
      analyze: (indicators) => request('/correlation/analyze', { method: 'POST', body: { indicators } }),
    },

    logs: {
      analyzeFile: (file) => {
        const form = new FormData();
        form.append('logFile', file);
        return request('/logs/analyze', { method: 'POST', body: form });
      },
      analyzeText: (logText) => request('/logs/analyze', { method: 'POST', body: { logText } }),
      reports: (limit = 20) => request(`/logs/reports?limit=${limit}`),
    },
  };

  global.CimiAPI = CimiAPI;
})(window);
