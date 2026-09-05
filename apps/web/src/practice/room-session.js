export function bytesToHex(value) {
  return Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(value) {
  return Uint8Array.from(value.match(/../g) || [], (byte) => Number.parseInt(byte, 16));
}

export function randomHex() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

export function toBase64(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeJson(value) {
  return toBase64(new TextEncoder().encode(JSON.stringify(value)));
}

export function decodeJson(value) {
  return JSON.parse(new TextDecoder().decode(fromBase64(value)));
}

export async function api(path, options = {}, token = null) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (${response.status})`);
  return body;
}

export function inviteLink(gameId, inviteSecret) {
  return `${location.origin}${location.pathname}#/join/${gameId}/${inviteSecret}`;
}

export function parseInvite(value) {
  let hash = value.trim();
  try { hash = new URL(hash).hash; } catch (_) {}
  let match = hash.match(/^#?\/join\/([0-9a-f]{64})\/([0-9a-f]{64})$/i);
  if (!match) match = value.trim().match(/^([0-9a-f]{64}):([0-9a-f]{64})$/i);
  if (!match) throw new Error("Invalid invite");
  return { gameId: match[1].toLowerCase(), inviteSecret: match[2].toLowerCase() };
}
