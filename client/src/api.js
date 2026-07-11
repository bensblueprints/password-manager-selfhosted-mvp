async function req(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options,
    body: options.body != null ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  bootstrap: () => req('/api/bootstrap'),
  prelogin: (email) => req('/api/prelogin', { method: 'POST', body: { email } }),
  register: (body) => req('/api/register', { method: 'POST', body }),
  login: (body) => req('/api/login', { method: 'POST', body }),
  logout: () => req('/api/logout', { method: 'POST' }),
  me: () => req('/api/me'),
  users: () => req('/api/users'),
  createInvite: (email) => req('/api/invites', { method: 'POST', body: { email } }),
  invites: () => req('/api/invites'),
  revokeUser: (id) => req(`/api/users/${id}/revoke`, { method: 'POST' }),
  vaults: () => req('/api/vaults'),
  createVault: (body) => req('/api/vaults', { method: 'POST', body }),
  vaultMembers: (id) => req(`/api/vaults/${id}/members`),
  shareVault: (id, body) => req(`/api/vaults/${id}/share`, { method: 'POST', body }),
  unshareVault: (id, userId) => req(`/api/vaults/${id}/share/${userId}`, { method: 'DELETE' }),
  items: () => req('/api/items'),
  createItem: (body) => req('/api/items', { method: 'POST', body }),
  updateItem: (id, body) => req(`/api/items/${id}`, { method: 'PUT', body }),
  deleteItem: (id) => req(`/api/items/${id}`, { method: 'DELETE' }),
  markAccessed: (id) => req(`/api/items/${id}/accessed`, { method: 'POST' }).catch(() => {}),
  audit: () => req('/api/audit'),
  exportOrg: () => req('/api/export')
};
