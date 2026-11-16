import { auth } from "./firebase";

const base = import.meta.env.VITE_API_BASE_URL || "https://mutah-hash-api.johnmutahi44.workers.dev";

export async function apiFile(path: string): Promise<Blob> {\n  const u = auth.currentUser;\n  if (!u) throw new Error("Please sign in.");\n  const token = await u.getIdToken();\n  const r = await fetch(base + path, { headers: { Authorization: "Bearer " + token } });\n  if (!r.ok) { let d: any = {}; try { d = await r.json(); } catch {} throw new Error(d.error || "Could not open supporting document."); }\n  return r.blob();\n}\n\nexport async function api(path: string, body?: unknown) {
  const u = auth.currentUser;
  if (!u) throw new Error("Please sign in.");
  const token = await u.getIdToken();
  const r = await fetch(base + path, {
    method: body !== undefined ? "POST" : "GET",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "Request failed");
  return d;
}
