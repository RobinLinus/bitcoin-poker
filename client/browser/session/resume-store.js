const HANDLE_PATTERN = /^[0-9a-f]{64}$/;
const GAME_ID_PATTERN = /^[0-9a-f]{64}$/;
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const MAX_RECORD_BYTES = 64 * 1024;
const SESSION_RECORD_VERSION = 3;
const PENDING_RECORD_VERSION = 3;

function requireHex(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} is malformed.`);
  }
  return value;
}

function requireStorage(storage) {
  if (!storage || typeof storage.getItem !== "function" ||
      typeof storage.setItem !== "function" || typeof storage.removeItem !== "function") {
    throw new Error("Browser storage is unavailable.");
  }
}

function safeJsonClone(value, label) {
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch (_) {
    throw new Error(`${label} is not serializable.`);
  }
  if (!encoded || new TextEncoder().encode(encoded).length > MAX_RECORD_BYTES) {
    throw new Error(`${label} exceeds the local storage limit.`);
  }
  let decoded;
  try {
    decoded = JSON.parse(encoded);
  } catch (_) {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error(`${label} must be an object.`);
  }
  return decoded;
}

function validateSession(session, deploymentDigestHex, expectedGameId = null) {
  const value = safeJsonClone(session, "Seat session");
  requireHex(value.gameId, GAME_ID_PATTERN, "Game id");
  requireHex(value.playerToken, TOKEN_PATTERN, "Player token");
  if (expectedGameId !== null && value.gameId !== expectedGameId) {
    throw new Error("The resume URL does not match the saved game.");
  }
  if (value.role !== "alice" && value.role !== "bob") {
    throw new Error("Seat role is malformed.");
  }
  if (value.inviteSecret !== undefined) {
    requireHex(value.inviteSecret, TOKEN_PATTERN, "Invite secret");
  }
  if (value.cursor === undefined) value.cursor = 0;
  if (!Number.isSafeInteger(value.cursor) || value.cursor < 0) {
    throw new Error("Relay cursor is malformed.");
  }
  value.joined = Boolean(value.joined);
  value.localReady = Boolean(value.localReady);
  value.peerReady = Boolean(value.peerReady);
  value.deploymentDigestHex = requireHex(
    deploymentDigestHex,
    DIGEST_PATTERN,
    "Deployment digest"
  );
  return value;
}

function validatePending(pending, deploymentDigestHex) {
  const value = safeJsonClone(pending, "Pending seat request");
  if (value.kind !== "create" && value.kind !== "join") {
    throw new Error("Pending request kind is malformed.");
  }
  requireHex(value.gameId, GAME_ID_PATTERN, "Game id");
  requireHex(value.playerToken, TOKEN_PATTERN, "Player token");
  requireHex(value.inviteSecret, TOKEN_PATTERN, "Invite secret");
  const expectedRole = value.kind === "create" ? "alice" : "bob";
  if (value.role !== expectedRole) throw new Error("Pending seat role is malformed.");
  if (value.cursor === undefined) value.cursor = 0;
  if (!Number.isSafeInteger(value.cursor) || value.cursor < 0) {
    throw new Error("Relay cursor is malformed.");
  }
  value.deploymentDigestHex = requireHex(
    deploymentDigestHex,
    DIGEST_PATTERN,
    "Deployment digest"
  );
  return value;
}

export function parseResumeRoute(hash) {
  if (typeof hash !== "string") return null;
  let match = hash.match(/^#\/game\/([0-9a-f]{64})\/resume\/([0-9a-f]{64})$/i);
  if (match) {
    return { kind: "game", gameId: match[1].toLowerCase(), handle: match[2].toLowerCase() };
  }
  match = hash.match(/^#\/resume\/([0-9a-f]{64})$/i);
  return match ? { kind: "pending", handle: match[1].toLowerCase() } : null;
}

export function gameResumeHash(gameId, handle) {
  return `#/game/${requireHex(gameId, GAME_ID_PATTERN, "Game id")}` +
    `/resume/${requireHex(handle, HANDLE_PATTERN, "Resume handle")}`;
}

export function pendingResumeHash(handle) {
  return `#/resume/${requireHex(handle, HANDLE_PATTERN, "Resume handle")}`;
}

export function randomResumeHandle(cryptoImplementation = globalThis.crypto) {
  if (!cryptoImplementation || typeof cryptoImplementation.getRandomValues !== "function") {
    throw new Error("Secure browser randomness is unavailable.");
  }
  const bytes = new Uint8Array(32);
  cryptoImplementation.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function createResumeStore({ deploymentDigestHex, storage }) {
  requireHex(deploymentDigestHex, DIGEST_PATTERN, "Deployment digest");
  requireStorage(storage);
  const sessionKey = (handle) =>
    `bp52.relay.session.v${SESSION_RECORD_VERSION}/${deploymentDigestHex}/` +
    requireHex(handle, HANDLE_PATTERN, "Resume handle");
  const pendingKey = (handle) =>
    `bp52.relay.pending.v${PENDING_RECORD_VERSION}/${deploymentDigestHex}/` +
    requireHex(handle, HANDLE_PATTERN, "Resume handle");

  function loadRecord(key, version, field) {
    const encoded = storage.getItem(key);
    if (encoded === null) return null;
    let envelope;
    try {
      envelope = JSON.parse(encoded);
    } catch (_) {
      throw new Error("Saved seat state is not valid JSON.");
    }
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) ||
        envelope.version !== version || envelope.deploymentDigestHex !== deploymentDigestHex) {
      throw new Error("Saved seat state belongs to a different deployment or version.");
    }
    return envelope[field];
  }

  function saveRecord(key, version, field, value) {
    const envelope = { version, deploymentDigestHex, [field]: value };
    const encoded = JSON.stringify(envelope);
    storage.setItem(key, encoded);
    if (storage.getItem(key) !== encoded) throw new Error("Browser storage did not retain seat state.");
  }

  return Object.freeze({
    loadSession(handle, expectedGameId = null) {
      const value = loadRecord(sessionKey(handle), SESSION_RECORD_VERSION, "session");
      return value === null ? null : validateSession(value, deploymentDigestHex, expectedGameId);
    },
    saveSession(handle, session) {
      const value = validateSession(session, deploymentDigestHex);
      saveRecord(sessionKey(handle), SESSION_RECORD_VERSION, "session", value);
      return value;
    },
    loadPending(handle) {
      const value = loadRecord(pendingKey(handle), PENDING_RECORD_VERSION, "pending");
      return value === null ? null : validatePending(value, deploymentDigestHex);
    },
    savePending(handle, pending) {
      const value = validatePending(pending, deploymentDigestHex);
      saveRecord(pendingKey(handle), PENDING_RECORD_VERSION, "pending", value);
      return value;
    },
    removePending(handle) {
      storage.removeItem(pendingKey(handle));
    },
  });
}
