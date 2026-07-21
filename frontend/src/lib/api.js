// Dev (Vite) serves the frontend and backend on different ports, so the API
// host has to be named explicitly — but by hostname, not a hardcoded
// "localhost", so a remote machine opening the dev server still reaches the
// right backend. The packaged/standalone build serves both from one origin,
// so a plain relative base just works there (and works remotely for free).
export const API = import.meta.env.DEV
  ? `${window.location.protocol}//${window.location.hostname}:3001/api`
  : `${window.location.origin}/api`;
