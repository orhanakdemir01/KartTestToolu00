// Remote-control auth: the backend trusts requests from itself (loopback)
// unconditionally, but requires a bearer token from anywhere else on the
// LAN. This module stores that token and transparently attaches it to every
// /api call, so the rest of the app can keep calling plain fetch().
const TOKEN_KEY = 'karttest_remote_token';

export function getRemoteToken() {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function setRemoteToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export const AUTH_REQUIRED_EVENT = 'karttest:remote-auth-required';

const nativeFetch = window.fetch.bind(window);

window.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : input?.url || '';
  const isApiCall = url.includes('/api/');
  if (isApiCall) {
    const token = getRemoteToken();
    if (token) init = { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } };
  }
  const res = await nativeFetch(input, init);
  if (isApiCall && res.status === 401) window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
  return res;
};
