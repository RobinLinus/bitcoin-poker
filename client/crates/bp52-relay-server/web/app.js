import { loadRuntimeConfig } from "/browser/config/runtime-config.js";
import {
  createBrowserEsploraChainAdapter,
} from "/browser/chain-adapter/esplora.js";
import {
  createBrowserGameFlow,
} from "/browser/flow/game-client.js";
import { GamePhase } from "/browser/game/game-runtime.js";
import {
  createBrowserChainGameFlow,
} from "/browser/flow/chain-game-client.js?v=12";
import {
  gameChainRefreshReady,
  localRoleMayAuthorizeEdge,
  nextGameplayPublishAction,
  recordAutomaticEdgeResult,
  selectAutomaticGameEdge,
} from "/browser/flow/orchestration.js";
import {
  OriginSpendDisposition,
  activationTxidFromProjection,
  bindExpectedActivationTxid,
  classifyOriginSpend,
} from "/browser/flow/game-chain-safety.js";
import {
  AutomaticSetupAction,
  agreedOriginPackageId,
  nextAutomaticSetupAction,
  originGameFlowReady,
  originInputsAreReady,
  playerSetupStatus,
  setupFailurePresentation,
  stagingFundingExchangePlan,
} from "/browser/flow/setup-planner.js?v=2";
import {
  acceptOpaqueRelayArtifact,
  durableRefundArtifacts,
  opaqueRelayArtifact,
  originBoundCommand,
  originCommandContext,
  originPackageCommand,
  originPublicationRequired,
} from "/browser/flow/origin-coordination.js";
import { tableBlindView } from "/browser/flow/table-stakes.js";
import { tableBalancesForViewer } from "/browser/flow/table-view.js";
import { formatBitcoinAmount } from "/browser/ui/bitcoin-amount.js";
import {
  createResumeStore,
  gameResumeHash,
  parseResumeRoute,
  pendingResumeHash,
  randomResumeHandle,
} from "/browser/session/resume-store.js";
import "/origin-client.js";

let RUNTIME_CONFIG;
try {
  RUNTIME_CONFIG = await loadRuntimeConfig();
} catch (error) {
  console.error("[BP52 config]", error);
  const target = document.getElementById("lobby-error");
  if (target) {
    target.textContent = "This table is unavailable. Reload the page to try again.";
    target.classList.remove("hidden");
  }
  throw error;
}

const { relay: RELAY_CONFIG, chain: CHAIN_CONFIG, game: GAME_CONFIG } = RUNTIME_CONFIG;
const RELAY_API_BASE_PATH = RELAY_CONFIG.apiBasePath;
const STORAGE_NAMESPACE = `${RUNTIME_CONFIG.deploymentId}.${RUNTIME_CONFIG.deploymentDigestHex}`;

const RESUME_STORE = createResumeStore({
  deploymentDigestHex: RUNTIME_CONFIG.deploymentDigestHex,
  storage: localStorage,
});
const POLL_INTERVAL_MS = RELAY_CONFIG.pollIntervalMs;
const REQUEST_TIMEOUT_MS = RELAY_CONFIG.requestTimeoutMs;
const MAX_RELAY_PAYLOAD_BASE64_BYTES = RELAY_CONFIG.maxPayloadBase64Bytes;
const READY_MESSAGE_KIND = RELAY_CONFIG.kinds.ready;
const READY_MESSAGE_PAYLOAD = "cmVhZHk=";
const NONCE_COMMIT_KIND = RELAY_CONFIG.kinds.nonceCommit;
const NONCE_REVEAL_KIND = RELAY_CONFIG.kinds.nonceReveal;
const NONCE_READY_KIND = RELAY_CONFIG.kinds.nonceReady;
const STAGING_FUNDING_KIND = RELAY_CONFIG.kinds.stagingFunding;
const ORIGIN_PACKAGE_KIND = RELAY_CONFIG.kinds.originPackage;
const ORIGIN_REFUND_SIGNATURE_KIND = RELAY_CONFIG.kinds.originRefundSignature;
const ORIGIN_FUNDING_SIGNATURE_KIND = RELAY_CONFIG.kinds.originFundingSignature;
const GAME_EXCHANGE_KIND = RELAY_CONFIG.kinds.gameExchange;
const CHAIN_EXCHANGE_KIND = RELAY_CONFIG.kinds.chainExchange;
const NONCE_COMMIT_TAG = "BP52/client/session-nonce-commit/v1";
const SESSION_NONCE_TAG = "BP52/client/session-nonce/v1";
const STAGING_WALLET_KEY_PREFIX = `bp52.${STORAGE_NAMESPACE}.staging-wallet.v3`;
const STAGING_WALLET_RECORD_VERSION = 2;
const ORIGIN_COORDINATOR_KEY_PREFIX = `bp52.${STORAGE_NAMESPACE}.origin-coordinator.v3`;
const ORIGIN_COORDINATOR_VERSION = 2;
const STAGING_DEPOSIT_SAT = GAME_CONFIG.stagingContributionSat;
const ORIGIN_REFUND_CSV_BLOCKS = GAME_CONFIG.refundCsvBlocks;
const CHAIN_NETWORK_ID_HEX = CHAIN_CONFIG.profileIdHex;
const MAX_ADDRESS_UTXOS = 128;
const MAX_ORIGIN_RAW_TX_HEX_CHARS = 32_768;
const elements = Object.fromEntries(
  [
    "lobby", "game", "create-tab", "join-tab", "create-panel", "join-panel",
    "deployment-name", "deployment-network", "funding-network-label",
    "create-game", "join-game", "invite-value", "join-hint", "lobby-error",
    "opponent-avatar", "opponent-name",
    "opponent-state", "opponent-stack", "opponent-blind", "local-avatar", "local-name",
    "local-stack", "local-blind", "table-small-blind", "table-big-blind",
    "funding-small-blind", "funding-big-blind",
    "table-phase", "table-detail",
    "invite-card", "share-link", "copy-link", "copy-state",
    "funding-card", "funding-amount", "funding-address", "copy-funding-address",
    "funding-state", "funding-local-input", "funding-peer-input", "funding-uri",
    "broadcast-refund", "game-pot", "action-bar", "action-fold",
    "action-check", "action-call", "action-aggressive", "action-timeout",
    "local-hole-cards", "hole-card-0", "hole-card-1", "board-card-0", "board-card-1",
    "board-card-2", "board-card-3", "board-card-4",
    "game-error"
  ].map((id) => [id, document.getElementById(id)])
);

const deploymentLabel = RUNTIME_CONFIG.deploymentId
  .split("-")
  .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
  .join(" ");
elements["deployment-name"].textContent = deploymentLabel;
elements["deployment-network"].textContent = `${deploymentLabel} ${CHAIN_CONFIG.network}`;
elements["funding-network-label"].textContent = `${deploymentLabel} · your seat`;

let resumeRoute = parseResumeRoute(location.hash);
let resumeHandle = resumeRoute?.handle ?? null;
let startupStorageError = null;
let session = loadSession();
let relayStatusKey = null;
let pollTimer = null;
let polling = false;
let pollController = null;
let preflightAdvancing = false;
let seatLockAttempt = 0;
let seatLockSession = null;
let seatLockRelease = null;
let seatLockBlocked = null;
let fundingEpoch = 0;
let fundingPreparing = false;
let fundingPollTimer = null;
let fundingPollController = null;
let fundingPollKey = null;
let fundingObservationVerified = false;
let stagingWalletContext = null;
let stagingExchangeAdvancing = false;
let stagingExchangeError = null;
let stagingExchangeHalted = false;
let stagingExchangeNextAttemptAt = 0;
let fundingFramesValidatedSession = null;
let peerFundingObservationVerified = false;
let peerFundingPollController = null;
let peerFundingNextCheckAt = 0;
let originEpoch = 0;
let originState = null;
let originStateSession = null;
let originAdvancing = false;
let originPackageVerified = false;
let originRefundVerified = false;
let originFundingVerified = false;
let originInputsLive = false;
let originError = null;
let originPackageContext = null;
let originPackagesAgreed = false;
let originInputController = null;
let originChainController = null;
let originChainObservation = null;
let originChainNextCheckAt = 0;
let originNextAttemptAt = 0;
let gameFlow = null;
let gameFlowSession = null;
let gameFlowStarting = null;
let gameFlowView = null;
let gameFlowError = null;
let chainGameFlow = null;
let chainGameView = null;
let chainGameError = null;
let gameProjectionBarrierDepth = 0;
let deferredGameProjection = null;
let chainAdapterPromise = null;
let originOutpointObservation = null;
let originTipObservation = null;
let expectedActivationTxid = null;
let refundBroadcasting = false;
let gameTransactionBroadcasting = false;
let activationAuthorizing = false;
let gameActionAuthorizing = false;
let automaticSetupRunning = false;
let automaticSetupNextAttemptAt = 0;
let gameplayAutomationScheduled = false;
let gameplayPublishNextAttemptAt = 0;
let gameplayEdgeNextAttemptAt = 0;
let gameplayPendingTxid = null;
let recoverySubmittedStep = null;
let automaticallyAuthorizedGameEdges = new Set();
let lastSetupDiagnostic = null;
let lastGameTipKey = null;
let lastConfirmedGameSpend = null;
const submittedGameTransactions = new Set();

class SessionProtocolError extends Error {}

function protocolError(message) {
  return new SessionProtocolError(message);
}

function ownsSeat(activeSession) {
  return activeSession !== null && seatLockSession === activeSession;
}

function sessionIsActive(activeSession) {
  return session === activeSession && ownsSeat(activeSession);
}

function randomHex(byteLength) {
  return bytesToHex(randomBytes(byteLength));
}

function randomBytes(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytes;
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
    throw protocolError("Invalid hexadecimal session value.");
  }
  return Uint8Array.from(hex.match(/../g), (byte) => Number.parseInt(byte, 16));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function encodeBase64Bytes(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeFixedBase64(value, byteLength) {
  if (typeof value !== "string" || value.length > 128) {
    throw protocolError("Invalid fixed-size session frame.");
  }
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytes.length !== byteLength || encodeBase64Bytes(bytes) !== value) {
      throw new Error("Invalid fixed-size session frame.");
    }
    return bytes;
  } catch (_) {
    throw protocolError("Invalid fixed-size session frame.");
  }
}

function concatBytes(...arrays) {
  const length = arrays.reduce((total, array) => total + array.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function taggedHash(tag, payload) {
  const tagHash = await sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, payload));
}

function fundingOperationIsActive(activeSession, epoch) {
  return fundingEpoch === epoch && sessionIsActive(activeSession);
}

function stagingWalletStorageKey(activeSession) {
  return `${STAGING_WALLET_KEY_PREFIX}/${activeSession.gameId}/${activeSession.role}`;
}

async function deriveStagingDescriptor(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) return null;
  const result = await callOriginHook("deriveStagingDescriptor", {
    privateKeyHex: bytesToHex(secret),
    walletNetworkCode: CHAIN_CONFIG.walletNetworkCode,
  });
  if (result && !result.address?.startsWith(`${CHAIN_CONFIG.addressHrp}1`)) {
    throw new Error("The local wallet returned an address for a different deployment.");
  }
  return result;
}

async function deriveStagingWallet(privateKeyHex) {
  if (!/^[0-9a-f]{64}$/.test(privateKeyHex)) {
    throw protocolError("Saved staging-wallet key material is malformed.");
  }
  const secret = hexToBytes(privateKeyHex);
  try {
    return await deriveStagingDescriptor(secret);
  } finally {
    secret.fill(0);
  }
}

async function loadOrCreateStagingWallet(activeSession, epoch) {
  const storageKey = stagingWalletStorageKey(activeSession);
  let stored = null;
  try {
    const encoded = localStorage.getItem(storageKey);
    if (encoded !== null) stored = JSON.parse(encoded);
  } catch (_) {
    throw protocolError("The saved staging wallet cannot be read safely.");
  }

  if (stored !== null) {
    if (
      stored.version !== STAGING_WALLET_RECORD_VERSION ||
      stored.network !== RUNTIME_CONFIG.deploymentId ||
      stored.deploymentDigestHex !== RUNTIME_CONFIG.deploymentDigestHex ||
      stored.gameId !== activeSession.gameId || stored.role !== activeSession.role ||
      typeof stored.address !== "string" || typeof stored.witnessScriptHex !== "string"
    ) {
      throw protocolError("The saved staging wallet has an unexpected context.");
    }
    const derived = await deriveStagingWallet(stored.privateKeyHex);
    if (!fundingOperationIsActive(activeSession, epoch)) return null;
    if (
      !derived || derived.address !== stored.address ||
      derived.witnessScriptHex !== stored.witnessScriptHex
    ) {
      throw protocolError("The saved staging wallet failed its local integrity check.");
    }
    return { ...stored, scriptPubKeyHex: derived.scriptPubKeyHex };
  }

  for (let attempt = 0; attempt < 16; attempt += 1) {
    const privateKey = randomBytes(32);
    const privateKeyHex = bytesToHex(privateKey);
    privateKey.fill(0);
    const derived = await deriveStagingWallet(privateKeyHex);
    if (!fundingOperationIsActive(activeSession, epoch)) return null;
    if (!derived) continue;
    const record = {
      version: STAGING_WALLET_RECORD_VERSION,
      network: RUNTIME_CONFIG.deploymentId,
      deploymentDigestHex: RUNTIME_CONFIG.deploymentDigestHex,
      gameId: activeSession.gameId,
      role: activeSession.role,
      privateKeyHex,
      address: derived.address,
      witnessScriptHex: derived.witnessScriptHex
    };
    const encoded = JSON.stringify(record);
    try {
      localStorage.setItem(storageKey, encoded);
      if (localStorage.getItem(storageKey) !== encoded) {
        throw new Error("Staging wallet did not round-trip.");
      }
    } catch (_) {
      throw protocolError("The staging key could not be persisted; no address was shown.");
    }
    return { ...record, scriptPubKeyHex: derived.scriptPubKeyHex };
  }
  throw new Error("Could not generate a valid staging key.");
}

function relayOriginArtifact(payload) {
  try {
    return opaqueRelayArtifact(payload, MAX_RELAY_PAYLOAD_BASE64_BYTES);
  } catch (_) {
    throw protocolError("Peer sent an invalid origin artifact.");
  }
}

function hookOriginArtifact(result, field) {
  try {
    return opaqueRelayArtifact(result?.[field], MAX_RELAY_PAYLOAD_BASE64_BYTES);
  } catch (_) {
    throw protocolError("The local origin engine returned an invalid artifact.");
  }
}

async function buildLocalStagingFundingFrame(activeSession, wallet) {
  const deposit = activeSession.stagingDeposit;
  if (
    !fundingObservationVerified || deposit?.status !== "confirmed" ||
    deposit.confirmed !== true || !/^[0-9a-f]{64}$/.test(deposit.txid || "") ||
    !Number.isSafeInteger(deposit.vout)
  ) {
    return null;
  }
  if (wallet.address !== deposit.address) {
    throw protocolError("The confirmed staging input does not belong to the active local key.");
  }
  const projection = {
    txid: deposit.txid,
    vout: deposit.vout,
    valueSat: deposit.valueSat,
    witnessScriptHex: wallet.witnessScriptHex,
    scriptPubKeyHex: wallet.scriptPubKeyHex
  };
  const result = await callOriginHook("buildStagingFrame", {
    ...originCommandContext(RUNTIME_CONFIG, activeSession),
    stagingFunding: projection,
  });
  if (!sessionIsActive(activeSession)) return null;
  return { projection, payload: hookOriginArtifact(result, "stagingFrame") };
}

async function validateStoredStagingFundingFrames(activeSession) {
  if (fundingFramesValidatedSession === activeSession) return true;
  if (activeSession.stagingFundingPayload) {
    relayOriginArtifact(activeSession.stagingFundingPayload);
  }
  if (activeSession.peerStagingFundingPayload) {
    relayOriginArtifact(activeSession.peerStagingFundingPayload);
  }
  if (activeSession.peerStagingFundingPayload) {
    activeSession.peerStagingFundingStatus ||= "pending";
  }
  peerFundingObservationVerified = false;
  fundingFramesValidatedSession = activeSession;
  saveSession(activeSession);
  return true;
}

async function nonceCommitment(role, gameId, share) {
  const roleCode = Uint8Array.of(role === "alice" ? 0 : 1);
  return taggedHash(NONCE_COMMIT_TAG, concatBytes(hexToBytes(gameId), roleCode, share));
}

async function deriveSessionNonce(gameId, hostShare, guestShare) {
  return taggedHash(
    SESSION_NONCE_TAG,
    concatBytes(hexToBytes(gameId), hostShare, guestShare)
  );
}

function loadSession() {
  if (resumeRoute) {
    if (resumeRoute.kind !== "game") return null;
    try {
      return RESUME_STORE.loadSession(resumeRoute.handle, resumeRoute.gameId);
    } catch (error) {
      startupStorageError = error instanceof Error ? error : new Error(String(error));
      return null;
    }
  }

  return null;
}

function saveSession(value) {
  if (!resumeHandle) throw new Error("This seat has no local resume handle.");
  const saved = RESUME_STORE.saveSession(resumeHandle, value);
  Object.assign(value, saved);
  session = value;
}

function setPendingResumeRoute() {
  if (resumeRoute?.kind !== "pending") resumeHandle = randomResumeHandle();
  resumeRoute = { kind: "pending", handle: resumeHandle };
  history.replaceState(null, "", pendingResumeHash(resumeHandle));
}

function setGameResumeRoute(gameId) {
  if (!resumeHandle) throw new Error("This seat has no local resume handle.");
  resumeRoute = { kind: "game", gameId, handle: resumeHandle };
  history.replaceState(null, "", gameResumeHash(gameId, resumeHandle));
}

function originCoordinatorStorageKey(activeSession) {
  return `${ORIGIN_COORDINATOR_KEY_PREFIX}/${activeSession.gameId}/${activeSession.role}`;
}

function freshOriginCoordinatorState(activeSession) {
  if (!/^[0-9a-f]{64}$/.test(activeSession.sessionNonce || "")) {
    throw protocolError("Origin coordinator cannot start before session nonce agreement.");
  }
  return {
    version: ORIGIN_COORDINATOR_VERSION,
    deploymentDigestHex: RUNTIME_CONFIG.deploymentDigestHex,
    networkId: CHAIN_NETWORK_ID_HEX,
    roomId: activeSession.gameId,
    sessionNonce: activeSession.sessionNonce,
    transportRole: activeSession.role,
    revision: 0
  };
}

function validateStoredOriginCoordinatorState(activeSession, value, encoded) {
  const allowedKeys = new Set([
    "version", "deploymentDigestHex", "networkId", "roomId", "sessionNonce",
    "transportRole", "revision",
    "setupAuthorizationPackageId",
    "localInputIndex",
    "localPackageMessageId", "localPackagePayload", "localPackageSent",
    "peerPackagePayload",
    "localRefundSignatureMessageId", "localRefundSignaturePayload",
    "localRefundSignatureSent", "peerRefundSignaturePayload", "signedRefundTxHex",
    "localFundingSignatureMessageId", "localFundingSignaturePayload",
    "localFundingSignatureSent", "peerFundingSignaturePayload", "signedFundingTxHex"
  ]);
  if (
    !value || typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    value.version !== ORIGIN_COORDINATOR_VERSION ||
    value.deploymentDigestHex !== RUNTIME_CONFIG.deploymentDigestHex ||
    value.networkId !== CHAIN_NETWORK_ID_HEX ||
    value.roomId !== activeSession.gameId || value.sessionNonce !== activeSession.sessionNonce ||
    !/^[0-9a-f]{64}$/.test(value.sessionNonce || "") ||
    value.transportRole !== activeSession.role ||
    !Number.isSafeInteger(value.revision) || value.revision < 0 || encoded.length > 131_072
  ) {
    throw protocolError("Saved origin coordinator state has an unexpected context.");
  }
  if (
    value.localInputIndex !== undefined &&
    value.localInputIndex !== 0 && value.localInputIndex !== 1
  ) {
    throw protocolError("Saved origin participant index is malformed.");
  }
  for (const key of [
    "localPackagePayload", "peerPackagePayload",
    "localRefundSignaturePayload", "peerRefundSignaturePayload",
    "localFundingSignaturePayload", "peerFundingSignaturePayload",
  ]) {
    if (value[key] !== undefined) relayOriginArtifact(value[key]);
  }
  for (const key of [
    "localPackageMessageId", "localRefundSignatureMessageId",
    "localFundingSignatureMessageId"
  ]) {
    if (value[key] !== undefined && !/^[0-9a-f]{64}$/.test(value[key])) {
      throw protocolError("Saved origin outbox identifier is malformed.");
    }
  }
  if (
    value.setupAuthorizationPackageId !== undefined &&
    !/^[0-9a-f]{64}$/.test(value.setupAuthorizationPackageId)
  ) {
    throw protocolError("Saved automatic-setup authorization is malformed.");
  }
  for (const key of [
    "localPackageSent", "localRefundSignatureSent", "localFundingSignatureSent"
  ]) {
    if (value[key] !== undefined && typeof value[key] !== "boolean") {
      throw protocolError("Saved origin outbox status is malformed.");
    }
  }
  for (const prefix of [
    "localPackage", "localRefundSignature", "localFundingSignature"
  ]) {
    if (value[`${prefix}MessageId`] && !value[`${prefix}Payload`]) {
      throw protocolError("Saved origin outbox identifier has no payload.");
    }
    if (
      value[`${prefix}Sent`] === true &&
      (!value[`${prefix}MessageId`] || !value[`${prefix}Payload`])
    ) {
      throw protocolError("Saved origin outbox completion is incomplete.");
    }
  }
  for (const key of ["signedRefundTxHex", "signedFundingTxHex"]) {
    if (
      value[key] !== undefined &&
      (!/^[0-9a-f]+$/.test(value[key]) || value[key].length % 2 !== 0 ||
        value[key].length > MAX_ORIGIN_RAW_TX_HEX_CHARS)
    ) {
      throw protocolError("Saved origin recovery transaction is malformed.");
    }
  }
  if (value.signedFundingTxHex && !value.signedRefundTxHex) {
    throw protocolError("Saved funding transaction exists without refund recovery.");
  }
}

function loadOriginCoordinatorState(activeSession) {
  if (originStateSession === activeSession && originState) return originState;
  const key = originCoordinatorStorageKey(activeSession);
  let value;
  try {
    const current = localStorage.getItem(key);
    if (current === null) {
      value = freshOriginCoordinatorState(activeSession);
    } else {
      value = JSON.parse(current);
      const encoded = JSON.stringify(value);
      validateStoredOriginCoordinatorState(activeSession, value, encoded);
    }
  } catch (error) {
    if (error instanceof SessionProtocolError) throw error;
    throw protocolError("Saved origin coordinator state cannot be read safely.");
  }
  originState = value;
  originStateSession = activeSession;
  originPackageVerified = false;
  originRefundVerified = false;
  originFundingVerified = false;
  originInputsLive = false;
  originPackageContext = null;
  originPackagesAgreed = false;
  return value;
}

function saveOriginCoordinatorState(activeSession) {
  if (!sessionIsActive(activeSession) || originStateSession !== activeSession || !originState) {
    throw protocolError("Origin coordinator lost its active player seat.");
  }
  const previousRevision = originState.revision;
  originState.revision += 1;
  const encoded = JSON.stringify(originState);
  try {
    validateStoredOriginCoordinatorState(activeSession, originState, encoded);
    const key = originCoordinatorStorageKey(activeSession);
    localStorage.setItem(key, encoded);
    if (localStorage.getItem(key) !== encoded) {
      throw new Error("Origin coordinator state did not round-trip.");
    }
  } catch (error) {
    originState.revision = previousRevision;
    if (error instanceof SessionProtocolError) throw error;
    throw protocolError("Origin coordinator state could not be persisted safely.");
  }
}

function readBackOriginCoordinatorState(activeSession) {
  try {
    const encoded = localStorage.getItem(originCoordinatorStorageKey(activeSession));
    if (encoded === null) {
      throw new Error("Origin coordinator state is missing after persistence.");
    }
    const value = JSON.parse(encoded);
    validateStoredOriginCoordinatorState(activeSession, value, encoded);
    originState = value;
    originStateSession = activeSession;
    return value;
  } catch (error) {
    if (error instanceof SessionProtocolError) throw error;
    throw protocolError("Durable origin coordinator state failed its read-back check.");
  }
}

function rememberExpectedActivationTxid(activeSession, candidate) {
  let next;
  try {
    next = bindExpectedActivationTxid(expectedActivationTxid, candidate);
  } catch (_) {
    throw protocolError("The authenticated activation transaction id changed or is malformed.");
  }
  if (!sessionIsActive(activeSession)) return null;
  expectedActivationTxid = next;
  return next;
}

function recoverExpectedActivationTxid(activeSession, projection) {
  let candidate;
  try {
    candidate = activationTxidFromProjection(projection);
  } catch (_) {
    throw protocolError("The reducer projected a malformed activation transaction id.");
  }
  return candidate === null ? null : rememberExpectedActivationTxid(activeSession, candidate);
}

function originHooks() {
  const hooks = globalThis.BP52_ORIGIN_COORDINATOR_HOOKS_V2;
  return hooks && typeof hooks === "object" ? hooks : null;
}

function originHookAvailable(name) {
  return typeof originHooks()?.[name] === "function";
}

async function callOriginHook(name, input) {
  const hook = originHooks()?.[name];
  if (typeof hook !== "function") {
    throw new Error("The local origin transaction builder is not connected yet.");
  }
  return hook(input);
}

async function sendStableOriginFrame(activeSession, prefix, kind, payload) {
  if (!sessionIsActive(activeSession)) return false;
  const state = loadOriginCoordinatorState(activeSession);
  const idField = `${prefix}MessageId`;
  const payloadField = `${prefix}Payload`;
  const sentField = `${prefix}Sent`;
  if (state[payloadField] && state[payloadField] !== payload) {
    throw protocolError("Saved origin outbox conflicts with the current package.");
  }
  if (state[sentField]) return true;
  state[idField] ||= randomHex(32);
  state[payloadField] = payload;
  saveOriginCoordinatorState(activeSession);
  await api(`${RELAY_API_BASE_PATH}/games/${activeSession.gameId}/messages`, {
    method: "POST",
    body: JSON.stringify({ messageId: state[idField], kind, payload })
  }, activeSession.playerToken);
  if (!sessionIsActive(activeSession) || originStateSession !== activeSession) return false;
  state[sentField] = true;
  saveOriginCoordinatorState(activeSession);
  return true;
}

function originOperationIsActive(activeSession, epoch) {
  return originEpoch === epoch && sessionIsActive(activeSession);
}

function originPublicHookInput(activeSession) {
  if (!activeSession.stagingFundingPayload || !activeSession.peerStagingFundingPayload) {
    throw protocolError("Both deposit announcements are required to prepare the game.");
  }
  try {
    return originPackageCommand(
      originCommandContext(RUNTIME_CONFIG, activeSession),
      activeSession.stagingFundingPayload,
      activeSession.peerStagingFundingPayload,
      MAX_RELAY_PAYLOAD_BASE64_BYTES,
    );
  } catch (_) {
    throw protocolError("Saved deposit announcements are invalid.");
  }
}

function validateBuiltOriginPackage(activeSession, result) {
  const packageFrame = hookOriginArtifact(result, "packageFrame");
  const peerPackageFrame = hookOriginArtifact(result, "peerPackageFrame");
  if (!result?.localStaging || !result.peerStaging) {
    throw protocolError("The local origin engine did not return deposit projections.");
  }
  activeSession.localStagingFunding = result.localStaging;
  activeSession.peerStagingFunding = result.peerStaging;
  activeSession.peerStagingFundingStatus ||= "pending";
  peerFundingObservationVerified = false;
  peerFundingNextCheckAt = 0;
  saveSession(activeSession);
  return {
    ...result,
    packageFrame,
    peerPackageFrame,
    packageInput: originPublicHookInput(activeSession),
    boundInput: null,
  };
}

function agreedOriginPackage(activeSession, state, packageContext = originPackageContext) {
  if (!state.localPackagePayload || !state.peerPackagePayload) return null;
  if (!packageContext || state.localPackagePayload !== packageContext.packageFrame) {
    throw protocolError("Saved and rebuilt origin packages differ.");
  }
  try {
    packageContext.boundInput = originBoundCommand(
      packageContext.packageInput,
      packageContext,
      state.peerPackagePayload,
      MAX_RELAY_PAYLOAD_BASE64_BYTES,
    );
  } catch (_) {
    throw protocolError("Players derived different origin packages.");
  }
  return { packageId: packageContext.packageId };
}

async function fetchConfirmedStagingFrame(frame, signal) {
  if (signal?.aborted) throw new DOMException("staging-input check aborted", "AbortError");
  const adapter = await loadChainAdapter();
  const outpoint = { displayTxid: hexToBytes(frame.txid), vout: frame.vout };
  const [fact, status] = await Promise.all([
    adapter.originFact({
      outpoint,
      valueSat: frame.valueSat,
      scriptPubkey: hexToBytes(frame.scriptPubKeyHex),
      minConfirmations: CHAIN_CONFIG.confirmations.origin,
    }),
    adapter.outpointStatus(outpoint),
  ]);
  if (signal?.aborted) throw new DOMException("staging-input check aborted", "AbortError");
  if (!fact) {
    throw protocolError("A selected deposit is not confirmed with the agreed output.");
  }
  if (status.state !== "unspent") {
    throw protocolError("A selected deposit is no longer unspent.");
  }
  return fact;
}

async function freshlyVerifyOriginInputs(activeSession, epoch) {
  if (!originOperationIsActive(activeSession, epoch)) return false;
  if (originInputController) {
    throw new Error("A fresh origin-input check is already running.");
  }
  const localFrame = activeSession.localStagingFunding;
  const peerFrame = activeSession.peerStagingFunding;
  if (!localFrame || !peerFrame) {
    throw protocolError("Both staging inputs must be known before authorization.");
  }
  const controller = new AbortController();
  originInputController = controller;
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  originInputsLive = false;
  try {
    await Promise.all([
      fetchConfirmedStagingFrame(localFrame, controller.signal),
      fetchConfirmedStagingFrame(peerFrame, controller.signal)
    ]);
    if (!originOperationIsActive(activeSession, epoch)) return false;
    originInputsLive = true;
    return true;
  } catch (error) {
    if (controller.signal.aborted && originOperationIsActive(activeSession, epoch)) {
      throw new Error("Fresh origin-input check timed out.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    if (originInputController === controller) originInputController = null;
  }
}

function validateSignedOriginTransaction(result, expectedTxid, label) {
  if (
    !/^[0-9a-f]+$/.test(result?.signedTxHex || "") ||
    result.signedTxHex.length % 2 !== 0 ||
    result.signedTxHex.length > MAX_ORIGIN_RAW_TX_HEX_CHARS ||
    result.txid !== expectedTxid
  ) {
    throw protocolError(`The local origin builder returned an invalid signed ${label}.`);
  }
  return { signedTxHex: result.signedTxHex, txid: result.txid };
}

function storedOriginSignatures(state) {
  const result = {
    localRefund: state.localRefundSignaturePayload
      ? relayOriginArtifact(state.localRefundSignaturePayload)
      : null,
    peerRefund: state.peerRefundSignaturePayload
      ? relayOriginArtifact(state.peerRefundSignaturePayload)
      : null,
    localFunding: state.localFundingSignaturePayload
      ? relayOriginArtifact(state.localFundingSignaturePayload)
      : null,
    peerFunding: state.peerFundingSignaturePayload
      ? relayOriginArtifact(state.peerFundingSignaturePayload)
      : null
  };
  if (state.signedRefundTxHex && (!result.localRefund || !result.peerRefund)) {
    throw protocolError("Saved refund recovery exists without both refund signatures.");
  }
  if (
    (result.localFunding || result.peerFunding || state.signedFundingTxHex) &&
    (!result.localRefund || !result.peerRefund)
  ) {
    throw protocolError("Funding authorization exists before both refund signatures.");
  }
  if ((result.localFunding || state.signedFundingTxHex) && !state.signedRefundTxHex) {
    throw protocolError("Local funding authorization exists before durable refund recovery.");
  }
  if (state.signedFundingTxHex && (!result.localFunding || !result.peerFunding)) {
    throw protocolError("Saved signed funding transaction lacks both signature shares.");
  }
  return result;
}

async function reconcileOriginArtifacts(activeSession, packageContext, epoch) {
  if (!originOperationIsActive(activeSession, epoch)) return;
  const state = loadOriginCoordinatorState(activeSession);
  const signatures = storedOriginSignatures(state);
  originRefundVerified = false;
  originFundingVerified = false;

  if (signatures.localRefund && signatures.peerRefund) {
    if (!originHookAvailable("verifyAndAssembleRefund")) return;
    const assembled = validateSignedOriginTransaction(
      await callOriginHook("verifyAndAssembleRefund", {
        ...packageContext.boundInput,
        localSignature: signatures.localRefund,
        peerSignature: signatures.peerRefund
      }),
      packageContext.refundTxid,
      "refund transaction"
    );
    if (!originOperationIsActive(activeSession, epoch)) return;
    if (state.signedRefundTxHex && state.signedRefundTxHex !== assembled.signedTxHex) {
      throw protocolError("Rebuilt refund transaction conflicts with durable recovery state.");
    }
    if (!state.signedRefundTxHex) {
      state.signedRefundTxHex = assembled.signedTxHex;
      saveOriginCoordinatorState(activeSession);
    }
    originRefundVerified = true;
  }

  if (signatures.localFunding || signatures.peerFunding || state.signedFundingTxHex) {
    if (!originRefundVerified) return;
    if (!signatures.localFunding || !signatures.peerFunding) return;
    if (!originHookAvailable("verifyAndAssembleFunding")) return;
    const protection = durableRefundArtifacts(state, MAX_RELAY_PAYLOAD_BASE64_BYTES);
    const assembled = validateSignedOriginTransaction(
      await callOriginHook("verifyAndAssembleFunding", {
        ...packageContext.boundInput,
        localSignature: signatures.localFunding,
        peerSignature: signatures.peerFunding,
        ...protection,
      }),
      packageContext.fundingTxid,
      "funding transaction"
    );
    if (!originOperationIsActive(activeSession, epoch)) return;
    if (state.signedFundingTxHex && state.signedFundingTxHex !== assembled.signedTxHex) {
      throw protocolError("Rebuilt funding transaction conflicts with durable signed state.");
    }
    if (!state.signedFundingTxHex) {
      state.signedFundingTxHex = assembled.signedTxHex;
      saveOriginCoordinatorState(activeSession);
    }
    originFundingVerified = true;
  }
}

async function pollOriginChainStatus(activeSession, packageContext, epoch, force = false) {
  if (
    !originOperationIsActive(activeSession, epoch) || originChainController ||
    (!force && Date.now() < originChainNextCheckAt)
  ) return originChainObservation;
  const controller = new AbortController();
  originChainController = controller;
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  originChainNextCheckAt = Date.now() + POLL_INTERVAL_MS;
  try {
    const adapter = await loadChainAdapter();
    const status = await adapter.transactionStatus(
      hexToBytes(packageContext.fundingTxid),
    );
    if (!originOperationIsActive(activeSession, epoch)) return null;
    if (status.state === "unknown") {
      originChainObservation = {
        txid: packageContext.fundingTxid,
        found: false,
        confirmed: false
      };
      return originChainObservation;
    }
    if (status.state === "reorged") {
      throw protocolError("The origin confirmation was removed from the configured best chain.");
    }
    originChainObservation = {
      txid: packageContext.fundingTxid,
      found: true,
      confirmed: status.state === "confirmed",
      ...(status.state === "confirmed"
        ? {
          blockHeight: status.block.height,
          blockHash: bytesToHex(status.block.displayHash),
        }
        : {})
    };
    if (originChainObservation.confirmed) {
      await refreshOriginSafety(activeSession, packageContext, epoch);
    }
    return originChainObservation;
  } catch (error) {
    if (!originOperationIsActive(activeSession, epoch)) return null;
    if (error instanceof SessionProtocolError || stagingExchangeHalted) {
      throw error;
    }
    console.warn("[BP52 chain] Game deposit check will retry.", error);
    return null;
  } finally {
    clearTimeout(timeout);
    if (originChainController === controller) originChainController = null;
  }
}

function originHasChainReason(state) {
  return Boolean(state.signedFundingTxHex);
}

async function ensureOriginPackage(activeSession, epoch) {
  if (!originOperationIsActive(activeSession, epoch)) return;
  const built = validateBuiltOriginPackage(
    activeSession,
    await callOriginHook("buildPackage", originPublicHookInput(activeSession))
  );
  if (!originOperationIsActive(activeSession, epoch)) return;
  const state = loadOriginCoordinatorState(activeSession);
  if (state.localInputIndex !== undefined && state.localInputIndex !== built.localInputIndex) {
    throw protocolError("Saved and rebuilt origin participant ordering differ.");
  }
  if (state.localPackagePayload && state.localPackagePayload !== built.packageFrame) {
    throw protocolError("Saved and rebuilt origin packages differ.");
  }
  if (state.localInputIndex === undefined || !state.localPackagePayload) {
    state.localInputIndex = built.localInputIndex;
    state.localPackagePayload = built.packageFrame;
    saveOriginCoordinatorState(activeSession);
  }
  originPackageContext = built;
  originPackageVerified = true;
  await sendStableOriginFrame(
    activeSession,
    "localPackage",
    ORIGIN_PACKAGE_KIND,
    built.packageFrame,
  );
  if (!originOperationIsActive(activeSession, epoch)) return;

  originPackagesAgreed = Boolean(agreedOriginPackage(activeSession, state, built));
  if (!originPackagesAgreed) return;

  if (state.localRefundSignaturePayload) {
    await sendStableOriginFrame(
      activeSession,
      "localRefundSignature",
      ORIGIN_REFUND_SIGNATURE_KIND,
      state.localRefundSignaturePayload
    );
  }
  if (!originOperationIsActive(activeSession, epoch)) return;
  await reconcileOriginArtifacts(activeSession, built, epoch);
  if (!originOperationIsActive(activeSession, epoch)) return;

  if (state.localFundingSignaturePayload && originRefundVerified) {
    await sendStableOriginFrame(
      activeSession,
      "localFundingSignature",
      ORIGIN_FUNDING_SIGNATURE_KIND,
      state.localFundingSignaturePayload
    );
  }
  if (!originOperationIsActive(activeSession, epoch)) return;
  await reconcileOriginArtifacts(activeSession, built, epoch);
  if (!originOperationIsActive(activeSession, epoch)) return;

  if (originHasChainReason(state)) {
    await pollOriginChainStatus(activeSession, built, epoch);
  }
}

function originCoordinatorNeedsAdvance(activeSession, state) {
  if (!originPackageVerified || !state.localPackageSent) return true;
  if (state.peerPackagePayload && !originPackagesAgreed) return true;
  if (state.localRefundSignaturePayload && !state.localRefundSignatureSent) return true;
  if (
    state.localRefundSignaturePayload && state.peerRefundSignaturePayload &&
    !originRefundVerified && originHookAvailable("verifyAndAssembleRefund")
  ) return true;
  if (
    state.localFundingSignaturePayload && originRefundVerified &&
    !state.localFundingSignatureSent
  ) return true;
  if (
    state.localFundingSignaturePayload && state.peerFundingSignaturePayload &&
    !originFundingVerified && originHookAvailable("verifyAndAssembleFunding")
  ) return true;
  return originHasChainReason(state) && Date.now() >= originChainNextCheckAt;
}

function originPackageInputsReady(activeSession) {
  return Boolean(
    activeSession?.sessionNonce &&
    activeSession.peerNonceReady === activeSession.sessionNonce &&
    activeSession.stagingFundingSent &&
    activeSession.stagingFundingPayload &&
    activeSession.peerStagingFundingPayload
  );
}

async function advanceOriginCoordinator(activeSession = session) {
  if (
    originAdvancing || !sessionIsActive(activeSession) || !originHookAvailable("buildPackage") ||
    !originPackageInputsReady(activeSession) || Date.now() < originNextAttemptAt
  ) return;
  const state = loadOriginCoordinatorState(activeSession);
  if (!originCoordinatorNeedsAdvance(activeSession, state)) return;
  const epoch = originEpoch;
  originAdvancing = true;
  try {
    await ensureOriginPackage(activeSession, epoch);
    if (!originOperationIsActive(activeSession, epoch)) return;
    originError = null;
    originNextAttemptAt = 0;
  } catch (error) {
    if (!originOperationIsActive(activeSession, epoch)) return;
    originError = error instanceof Error ? error.message : "Origin coordination failed.";
    if (error instanceof SessionProtocolError) {
      stagingExchangeHalted = true;
      stagingExchangeError = originError;
      setRelayStatus("error", "Setup halted");
      showError(elements["game-error"], error);
    } else {
      originNextAttemptAt = Date.now() + POLL_INTERVAL_MS;
    }
  } finally {
    if (originEpoch === epoch) originAdvancing = false;
    if (sessionIsActive(activeSession)) updateSetupUi(Boolean(activeSession.joined));
  }
}

function scheduleOriginCoordinator(activeSession = session) {
  if (
    !sessionIsActive(activeSession) || stagingExchangeHalted || originAdvancing ||
    !originPackageInputsReady(activeSession) || !originHookAvailable("buildPackage") ||
    Date.now() < originNextAttemptAt
  ) return;
  let state;
  try {
    state = loadOriginCoordinatorState(activeSession);
  } catch (error) {
    originError = error instanceof Error ? error.message : "Saved origin state is invalid.";
    stagingExchangeHalted = true;
    stagingExchangeError = originError;
    setRelayStatus("error", "Setup halted");
    showError(elements["game-error"], error);
    return;
  }
  if (originCoordinatorNeedsAdvance(activeSession, state)) {
    void advanceOriginCoordinator(activeSession);
  }
}

function loadPending(kind, invitation = null) {
  if (!resumeHandle || resumeRoute?.kind !== "pending") return null;
  try {
    const value = RESUME_STORE.loadPending(resumeHandle);
    if (!value || value.kind !== kind) return null;
    if (kind === "join" && value.gameId !== invitation?.gameId) return null;
    return value;
  } catch (error) {
    throw error instanceof Error ? error : new Error("Saved seat request is invalid.");
  }
}

function savePending(value) {
  if (!resumeHandle) throw new Error("This seat has no local resume handle.");
  RESUME_STORE.savePending(resumeHandle, value);
}

function clearPending() {
  if (resumeHandle) RESUME_STORE.removePending(resumeHandle);
}

function loadStartupPending() {
  if (session) return null;
  try {
    return resumeRoute?.kind === "pending" ? RESUME_STORE.loadPending(resumeHandle) : null;
  } catch (error) {
    startupStorageError = error instanceof Error ? error : new Error(String(error));
    return null;
  }
}

async function api(path, options = {}, token = null) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  const timeoutController = options.signal ? null : new AbortController();
  const timeout = timeoutController
    ? setTimeout(() => timeoutController.abort(), REQUEST_TIMEOUT_MS)
    : null;
  try {
    const response = await fetch(path, {
      ...options,
      headers,
      cache: "no-store",
      signal: options.signal || timeoutController.signal
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = body?.error?.message || `Relay request failed (${response.status})`;
      throw new Error(message);
    }
    return body;
  } catch (error) {
    if (timeoutController?.signal.aborted) throw new Error("Relay request timed out.");
    throw error;
  } finally {
    if (timeout !== null) clearTimeout(timeout);
  }
}

function setBusy(button, busy) {
  button.disabled = busy;
  button.setAttribute("aria-busy", String(busy));
}

function setTableStatus(headline, detail, busy = false) {
  elements["table-phase"].textContent = headline;
  elements["table-phase"].classList.toggle("busy", busy);
  elements["table-detail"].textContent = detail;
}

function showError(target, error) {
  const diagnostic = error instanceof Error ? error.message : String(error);
  console.error("[BP52]", error);
  if (target === elements["game-error"]) {
    const halted = error instanceof SessionProtocolError;
    setTableStatus(
      halted ? "Couldn’t continue" : "Reconnecting…",
      halted ? "Reload the page to try again." : "We’ll keep trying automatically.",
      !halted,
    );
    target.textContent = "";
    target.classList.add("hidden");
    return;
  }
  target.textContent = diagnostic === "That invite link is not valid."
    ? diagnostic
    : "Couldn’t open the table. Check the invite and try again.";
  target.classList.remove("hidden");
}

function clearError(target) {
  target.textContent = "";
  target.classList.add("hidden");
}

function selectTab(name) {
  const creating = name === "create";
  elements["create-tab"].classList.toggle("active", creating);
  elements["join-tab"].classList.toggle("active", !creating);
  elements["create-tab"].setAttribute("aria-selected", String(creating));
  elements["join-tab"].setAttribute("aria-selected", String(!creating));
  elements["create-panel"].classList.toggle("hidden", !creating);
  elements["join-panel"].classList.toggle("hidden", creating);
  clearError(elements["lobby-error"]);
}

function parseInvite(value) {
  const trimmed = value.trim();
  try {
    const url = new URL(trimmed);
    return parseInviteHash(url.hash);
  } catch (_) {
    const [gameId, inviteSecret] = trimmed.split(":");
    if (/^[0-9a-f]{64}$/i.test(gameId || "") && /^[0-9a-f]{64}$/i.test(inviteSecret || "")) {
      return { gameId: gameId.toLowerCase(), inviteSecret: inviteSecret.toLowerCase() };
    }
  }
  throw new Error("That invite link is not valid.");
}

function parseInviteHash(hash) {
  const match = hash.match(/^#\/join\/([0-9a-f]{64})\/([0-9a-f]{64})$/i);
  if (!match) throw new Error("That invite link is not valid.");
  return { gameId: match[1].toLowerCase(), inviteSecret: match[2].toLowerCase() };
}

function inviteLink(gameId, inviteSecret) {
  return `${location.origin}${location.pathname}${location.search}#/join/${gameId}/${inviteSecret}`;
}

async function createGame(pendingRequest = null) {
  clearError(elements["lobby-error"]);
  setBusy(elements["create-game"], true);
  try {
    if (resumeRoute?.kind !== "pending") setPendingResumeRoute();
    const next = pendingRequest || loadPending("create") || {
      kind: "create",
      gameId: randomHex(32),
      playerToken: randomHex(32),
      inviteSecret: randomHex(32),
      role: "alice",
      cursor: 0
    };
    savePending(next);
    await api(`${RELAY_API_BASE_PATH}/games`, {
      method: "POST",
      body: JSON.stringify({
        gameId: next.gameId,
        playerToken: next.playerToken,
        inviteSecret: next.inviteSecret
      })
    });
    saveSession({
      gameId: next.gameId,
      playerToken: next.playerToken,
      inviteSecret: next.inviteSecret,
      role: next.role,
      cursor: next.cursor,
      joined: false,
      localReady: false,
      peerReady: false
    });
    clearPending();
    setGameResumeRoute(next.gameId);
    showGame();
  } catch (error) {
    showError(elements["lobby-error"], error);
  } finally {
    setBusy(elements["create-game"], false);
  }
}

async function joinGame(pendingRequest = null) {
  clearError(elements["lobby-error"]);
  setBusy(elements["join-game"], true);
  try {
    const invitation = pendingRequest
      ? { gameId: pendingRequest.gameId, inviteSecret: pendingRequest.inviteSecret }
      : parseInvite(elements["invite-value"].value);
    if (resumeRoute?.kind !== "pending") setPendingResumeRoute();
    const next = pendingRequest || loadPending("join", invitation) || {
      kind: "join",
      gameId: invitation.gameId,
      playerToken: randomHex(32),
      inviteSecret: invitation.inviteSecret,
      role: "bob",
      cursor: 0
    };
    savePending(next);
    await api(`${RELAY_API_BASE_PATH}/games/${invitation.gameId}/join`, {
      method: "POST",
      body: JSON.stringify({
        playerToken: next.playerToken,
        inviteSecret: invitation.inviteSecret
      })
    });
    saveSession({
      gameId: next.gameId,
      playerToken: next.playerToken,
      role: next.role,
      cursor: next.cursor,
      joined: true,
      localReady: false,
      peerReady: false
    });
    clearPending();
    setGameResumeRoute(next.gameId);
    showGame();
  } catch (error) {
    showError(elements["lobby-error"], error);
  } finally {
    setBusy(elements["join-game"], false);
  }
}

function configureSeats() {
  const isAlice = session.role === "alice";
  elements["local-avatar"].textContent = isAlice ? "H" : "G";
  elements["local-name"].textContent = `You · ${isAlice ? "Host" : "Guest"}`;
  elements["opponent-avatar"].textContent = isAlice ? "G" : "H";
  elements["opponent-name"].textContent = isAlice ? "Guest" : "Host";
  elements["invite-card"].classList.toggle("hidden", !isAlice);
  if (isAlice && session.inviteSecret) {
    elements["share-link"].value = inviteLink(session.gameId, session.inviteSecret);
  }
}

function releaseSeatLock() {
  stopStagingDeposit(true);
  seatLockAttempt += 1;
  seatLockBlocked = null;
  seatLockSession = null;
  const release = seatLockRelease;
  seatLockRelease = null;
  if (release) release();
}

function claimSeatLock(activeSession) {
  releaseSeatLock();
  const attempt = seatLockAttempt;
  if (!navigator.locks?.request) {
    seatLockBlocked = "unsupported";
    updateSetupUi(Boolean(activeSession.joined));
    return;
  }

  const lockName = `bp52/relay-seat/v1/${activeSession.gameId}/${activeSession.playerToken}`;
  void navigator.locks.request(lockName, { mode: "exclusive", ifAvailable: true }, async (lock) => {
    if (attempt !== seatLockAttempt || session !== activeSession) return;
    if (!lock) {
      seatLockBlocked = "other-tab";
      updateSetupUi(Boolean(activeSession.joined));
      return;
    }

    seatLockBlocked = null;
    seatLockSession = activeSession;
    updateSetupUi(Boolean(activeSession.joined));
    await new Promise((resolve) => { seatLockRelease = resolve; });
    if (seatLockSession === activeSession) {
      seatLockSession = null;
      stopStagingDeposit(true);
    }
  }).catch(() => {
    if (attempt !== seatLockAttempt || session !== activeSession) return;
    seatLockBlocked = "unsupported";
    updateSetupUi(Boolean(activeSession.joined));
  });
}

function showGame() {
  if (!session) return showLobby();
  const activeSession = session;
  elements.lobby.classList.add("hidden");
  elements.game.classList.remove("hidden");
  configureSeats();
  updateSetupUi(Boolean(activeSession.joined));
  clearError(elements["game-error"]);
  claimSeatLock(activeSession);
  startPolling();
}

function showLobby() {
  releaseSeatLock();
  if (pollTimer) clearInterval(pollTimer);
  if (pollController) pollController.abort();
  pollTimer = null;
  pollController = null;
  elements.game.classList.add("hidden");
  elements.lobby.classList.remove("hidden");
  const hashInvite = location.hash.startsWith("#/join/") ? location.href : null;
  if (hashInvite) {
    selectTab("join");
    elements["invite-value"].value = hashInvite;
    elements["join-hint"].textContent = "Invite recognized. Join to claim the guest seat.";
  }
  if (startupStorageError) {
    showError(elements["lobby-error"], startupStorageError);
    startupStorageError = null;
  }
}

function setRelayStatus(kind, label) {
  const next = `${kind}:${label}`;
  if (next === relayStatusKey) return;
  relayStatusKey = next;
  console.debug("[BP52 relay]", label);
}

function stopStagingDeposit(clearDisplay) {
  stopOriginCoordinator(clearDisplay);
  fundingEpoch += 1;
  fundingPreparing = false;
  fundingPollKey = null;
  fundingObservationVerified = false;
  stagingWalletContext = null;
  stagingExchangeAdvancing = false;
  stagingExchangeError = null;
  stagingExchangeHalted = false;
  stagingExchangeNextAttemptAt = 0;
  fundingFramesValidatedSession = null;
  peerFundingObservationVerified = false;
  peerFundingNextCheckAt = 0;
  if (fundingPollTimer) clearInterval(fundingPollTimer);
  if (fundingPollController) fundingPollController.abort();
  if (peerFundingPollController) peerFundingPollController.abort();
  fundingPollTimer = null;
  fundingPollController = null;
  peerFundingPollController = null;
  if (clearDisplay) {
    elements["funding-card"].classList.add("hidden");
    elements["funding-address"].value = "";
    elements["funding-uri"].removeAttribute("href");
    elements["funding-local-input"].textContent = "Not confirmed";
    elements["funding-peer-input"].textContent = "Waiting";
  }
}

function stopOriginCoordinator(clearDisplay) {
  stopGameFlow();
  originEpoch += 1;
  if (originInputController) originInputController.abort();
  if (originChainController) originChainController.abort();
  originState = null;
  originStateSession = null;
  originAdvancing = false;
  originPackageVerified = false;
  originRefundVerified = false;
  originFundingVerified = false;
  originInputsLive = false;
  originError = null;
  originPackageContext = null;
  originPackagesAgreed = false;
  originInputController = null;
  originChainController = null;
  originChainObservation = null;
  originOutpointObservation = null;
  originTipObservation = null;
  expectedActivationTxid = null;
  refundBroadcasting = false;
  originChainNextCheckAt = 0;
  originNextAttemptAt = 0;
  if (clearDisplay) {
    elements["broadcast-refund"].disabled = true;
    elements["broadcast-refund"].classList.add("hidden");
  }
}

function setFundingStatus(activeSession, kind, message, observation = null) {
  if (!sessionIsActive(activeSession)) return;
  elements["funding-state"].className = `funding-state ${kind}`;
  elements["funding-state"].textContent = message;
  activeSession.stagingDeposit = {
    address: elements["funding-address"].value,
    amountSat: STAGING_DEPOSIT_SAT,
    status: kind,
    ...(observation || {})
  };
  saveSession(activeSession);
  updateSetupUi(Boolean(activeSession.joined));
}

function durableLocalStagingSelection(activeSession) {
  const originPackageSaved = originStateSession === activeSession &&
    Boolean(originState?.localPackagePayload);
  if (
    !activeSession?.localStagingFunding && !activeSession?.stagingFundingPayload &&
    !originPackageSaved
  ) {
    return null;
  }
  const frame = activeSession.stagingDeposit;
  if (
    !frame || typeof frame.address !== "string" ||
    !/^[0-9a-f]{64}$/.test(frame.txid || "") ||
    !Number.isSafeInteger(frame.vout) || frame.vout < 0 || frame.vout > 0xffff_ffff ||
    frame.valueSat !== STAGING_DEPOSIT_SAT
  ) {
    throw protocolError("Saved local staging-input selection is malformed.");
  }
  return {
    address: frame.address,
    txid: frame.txid,
    vout: frame.vout,
    valueSat: frame.valueSat
  };
}

function expectedOriginFundingTxid(activeSession) {
  return sessionIsActive(activeSession) ? originPackageContext?.fundingTxid ?? null : null;
}

function extraDepositSuffix(count) {
  return count > 0
    ? " Another payment was detected; only one will be used."
    : "";
}

function renderStagingWallet(activeSession, wallet) {
  if (!sessionIsActive(activeSession)) return;
  stagingWalletContext = { activeSession, wallet, epoch: fundingEpoch };
  elements["funding-amount"].textContent = formatBitcoinAmount(STAGING_DEPOSIT_SAT);
  elements["funding-address"].value = wallet.address;
  const wholeCoins = Math.floor(STAGING_DEPOSIT_SAT / 100_000_000);
  const fractionalCoins = String(STAGING_DEPOSIT_SAT % 100_000_000).padStart(8, "0");
  elements["funding-uri"].href =
    `bitcoin:${wallet.address}?amount=${wholeCoins}.${fractionalCoins}&label=BP52%20${encodeURIComponent(RUNTIME_CONFIG.deploymentId)}%20seat`;
  elements["funding-card"].classList.remove("hidden");
  const selection = durableLocalStagingSelection(activeSession);
  if (selection) {
    if (selection.address !== wallet.address) {
      throw protocolError("The saved staging-input selection belongs to another local key.");
    }
    setFundingStatus(
      activeSession,
      "checking",
      "Checking your saved deposit…",
      selection
    );
  } else {
    setFundingStatus(
      activeSession,
      "waiting",
      `Waiting for your exact ${formatBitcoinAmount(STAGING_DEPOSIT_SAT)} deposit…`
    );
  }
}

function setPeerFundingStatus(activeSession, status, observation = null) {
  if (!sessionIsActive(activeSession) || !activeSession.peerStagingFunding) return;
  activeSession.peerStagingFundingStatus = status;
  activeSession.peerStagingFundingObservation = observation;
  peerFundingObservationVerified = status === "verified";
  saveSession(activeSession);
  updateSetupUi(Boolean(activeSession.joined));
}

async function verifyPeerStagingFunding(activeSession, epoch) {
  const frame = activeSession.peerStagingFunding;
  if (
    !frame || peerFundingObservationVerified || peerFundingPollController ||
    Date.now() < peerFundingNextCheckAt || !fundingOperationIsActive(activeSession, epoch)
  ) return;
  const expectedFundingTxid = expectedOriginFundingTxid(activeSession);
  if (
    expectedFundingTxid && originChainObservation?.found &&
    originChainObservation.txid === expectedFundingTxid
  ) {
    peerFundingNextCheckAt = Number.POSITIVE_INFINITY;
    setPeerFundingStatus(activeSession, "spent-origin", {
      txid: frame.txid,
      vout: frame.vout,
      valueSat: frame.valueSat,
      spendingTxid: expectedFundingTxid,
      confirmed: Boolean(originChainObservation.confirmed)
    });
    return;
  }

  const controller = new AbortController();
  peerFundingPollController = controller;
  peerFundingNextCheckAt = Date.now() + POLL_INTERVAL_MS;
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  setPeerFundingStatus(activeSession, "checking");
  try {
    const adapter = await loadChainAdapter();
    const outpoint = { displayTxid: hexToBytes(frame.txid), vout: frame.vout };
    const [fact, status] = await Promise.all([
      adapter.originFact({
        outpoint,
        valueSat: frame.valueSat,
        scriptPubkey: hexToBytes(frame.scriptPubKeyHex),
        minConfirmations: CHAIN_CONFIG.confirmations.origin,
      }),
      adapter.outpointStatus(outpoint),
    ]);
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    if (!fact) {
      setPeerFundingStatus(activeSession, "waiting");
      return;
    }
    if (status.state === "spent") {
      const spendingTxid = bytesToHex(status.spendingDisplayTxid);
      if (expectedFundingTxid && spendingTxid === expectedFundingTxid) {
        peerFundingNextCheckAt = Number.POSITIVE_INFINITY;
        setPeerFundingStatus(activeSession, "spent-origin", {
          txid: frame.txid,
          vout: frame.vout,
          valueSat: frame.valueSat,
          spendingTxid,
          confirmed: status.spendingStatus.state === "confirmed",
        });
        return;
      }
      throw protocolError("The opponent's deposit was spent by another transaction.");
    }
    if (status.state !== "unspent") {
      setPeerFundingStatus(activeSession, "waiting");
      return;
    }
    peerFundingNextCheckAt = Number.POSITIVE_INFINITY;
    setPeerFundingStatus(activeSession, "verified", {
      txid: frame.txid,
      vout: frame.vout,
      valueSat: frame.valueSat,
      confirmed: true,
      blockHeight: fact.confirmedIn.height,
      blockHash: bytesToHex(fact.confirmedIn.displayHash)
    });
  } catch (error) {
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    if (error instanceof SessionProtocolError) throw error;
    setPeerFundingStatus(activeSession, "error");
  } finally {
    clearTimeout(timeout);
    if (peerFundingPollController === controller) peerFundingPollController = null;
  }
}

async function advanceStagingFundingExchange(activeSession, wallet, epoch) {
  if (
    stagingExchangeAdvancing || !fundingOperationIsActive(activeSession, epoch) ||
    !activeSession.sessionNonce || activeSession.peerNonceReady !== activeSession.sessionNonce
  ) return;
  stagingExchangeAdvancing = true;
  try {
    if (!await validateStoredStagingFundingFrames(activeSession)) return;
    if (!fundingOperationIsActive(activeSession, epoch)) return;

    const local = await buildLocalStagingFundingFrame(activeSession, wallet);
    if (local) {
      if (
        activeSession.stagingFundingPayload &&
        activeSession.stagingFundingPayload !== local.payload
      ) {
        throw protocolError("Saved staging-input outbox conflicts with the confirmed local input.");
      }
      activeSession.localStagingFunding = local.projection;
      saveSession(activeSession);
      if (!await sendStableSessionFrame(
        activeSession,
        "stagingFunding",
        STAGING_FUNDING_KIND,
        local.payload
      )) return;
    }
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    await verifyPeerStagingFunding(activeSession, epoch);
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    stagingExchangeError = null;
    stagingExchangeNextAttemptAt = 0;
  } finally {
    stagingExchangeAdvancing = false;
    if (fundingOperationIsActive(activeSession, epoch)) {
      updateSetupUi(Boolean(activeSession.joined));
    }
  }
}

function scheduleStagingFundingExchange(activeSession = session) {
  const context = stagingWalletContext;
  const localDepositConfirmed = fundingObservationVerified &&
    activeSession?.stagingDeposit?.status === "confirmed" &&
    activeSession.stagingDeposit.confirmed === true;
  const now = Date.now();
  const work = stagingFundingExchangePlan({
    storedFramesValidated: fundingFramesValidatedSession === activeSession,
    localPayloadPresent: Boolean(activeSession?.stagingFundingPayload),
    peerPayloadPresent: Boolean(activeSession?.peerStagingFundingPayload),
    localDepositConfirmed,
    localFrameSent: Boolean(activeSession?.stagingFundingSent),
    peerFramePresent: Boolean(activeSession?.peerStagingFunding),
    peerObservationVerified: peerFundingObservationVerified,
    peerCheckAt: peerFundingNextCheckAt,
    now,
  });
  if (
    !context || context.activeSession !== activeSession ||
    stagingExchangeHalted ||
    !work.shouldSchedule ||
    now < stagingExchangeNextAttemptAt || !fundingOperationIsActive(activeSession, context.epoch)
  ) return;
  void advanceStagingFundingExchange(activeSession, context.wallet, context.epoch).catch((error) => {
    if (!fundingOperationIsActive(activeSession, context.epoch)) return;
    if (error instanceof SessionProtocolError) {
      stagingExchangeHalted = true;
      stagingExchangeError = error.message;
      setRelayStatus("error", "Setup halted");
      showError(elements["game-error"], error);
      updateSetupUi(Boolean(activeSession.joined));
      return;
    }
    stagingExchangeError = error instanceof Error
      ? `${error.message} Retrying the deposit check.`
      : "Deposit check failed; retrying.";
    stagingExchangeNextAttemptAt = Date.now() + POLL_INTERVAL_MS;
    updateSetupUi(Boolean(activeSession.joined));
  });
}

async function pollStagingDeposit(activeSession, wallet, epoch) {
  if (!fundingOperationIsActive(activeSession, epoch) || fundingPollController) return;
  const controller = new AbortController();
  fundingPollController = controller;
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const adapter = await loadChainAdapter();
    const utxos = await adapter.addressUtxos(wallet.address, {
      maximum: MAX_ADDRESS_UTXOS,
    });
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    fundingObservationVerified = true;
    const exact = utxos.filter((utxo) => utxo.value === STAGING_DEPOSIT_SAT);
    const selection = durableLocalStagingSelection(activeSession);
    if (selection) {
      if (selection.address !== wallet.address) {
        throw protocolError("The selected staging input belongs to another local key.");
      }
      const selectedMatches = utxos.filter(
        (utxo) => utxo.txid === selection.txid && utxo.vout === selection.vout
      );
      if (selectedMatches.length > 1) {
        throw protocolError("The chain backend returned the selected staging input more than once.");
      }
      const additionalDeposits = exact.filter(
        (utxo) => utxo.txid !== selection.txid || utxo.vout !== selection.vout
      ).length;
      const expectedFundingTxid = expectedOriginFundingTxid(activeSession);
      const expectedOriginSeen = Boolean(
        expectedFundingTxid && originChainObservation?.found &&
        originChainObservation.txid === expectedFundingTxid
      );
      if (expectedOriginSeen) {
        setFundingStatus(
          activeSession,
          "spent-origin",
          `Your deposit is in the game.${extraDepositSuffix(additionalDeposits)}`,
          {
            ...selection,
            confirmed: false,
            spendingTxid: expectedFundingTxid,
            spentByExpectedOrigin: true
          }
        );
        return;
      }
      if (selectedMatches.length === 0) {
        const outpointStatus = await adapter.outpointStatus({
          displayTxid: hexToBytes(selection.txid),
          vout: selection.vout
        });
        if (!fundingOperationIsActive(activeSession, epoch)) return;
        if (outpointStatus.state === "spent") {
          const spendingTxid = bytesToHex(outpointStatus.spendingDisplayTxid);
          if (expectedFundingTxid && spendingTxid !== expectedFundingTxid) {
            throw protocolError(
              `Your saved deposit was spent outside this game (${
                spendingTxid.slice(0, 12)
              }…).`
            );
          }
          if (expectedFundingTxid) {
            setFundingStatus(
            activeSession,
            "spent-origin",
              `Your deposit is in the game.${
                extraDepositSuffix(additionalDeposits)
              }`,
              {
                ...selection,
                confirmed: false,
                spendingTxid,
                spentByExpectedOrigin: true
              }
            );
            return;
          }
          fundingObservationVerified = false;
          setFundingStatus(
            activeSession,
            "checking",
            `Checking your deposit…${extraDepositSuffix(additionalDeposits)}`,
            { ...selection, confirmed: false, spendingTxid }
          );
          return;
        }
        fundingObservationVerified = false;
        setFundingStatus(
          activeSession,
          "checking",
          `Checking your deposit again…${extraDepositSuffix(additionalDeposits)}`,
          { ...selection, confirmed: false }
        );
        return;
      }

      const [utxo] = selectedMatches;
      if (utxo.value !== selection.valueSat) {
        throw protocolError("The selected staging-input value conflicts with its saved binding.");
      }
      const observation = {
        ...selection,
        confirmed: utxo.status.confirmed
      };
      if (utxo.status.confirmed) {
        observation.blockHeight = utxo.status.block_height;
        observation.blockHash = utxo.status.block_hash;
        setFundingStatus(
          activeSession,
          "confirmed",
          `Your deposit is confirmed.${extraDepositSuffix(additionalDeposits)}`,
          observation
        );
      } else {
        setFundingStatus(
          activeSession,
          "seen",
          `Deposit received. Waiting for one confirmation.${
            extraDepositSuffix(additionalDeposits)
          }`,
          observation
        );
      }
      return;
    }
    if (exact.length === 0) {
      const message = utxos.length === 0
        ? `Waiting for your exact ${formatBitcoinAmount(STAGING_DEPOSIT_SAT)} deposit…`
        : `No exact deposit found. Send one payment of exactly ${formatBitcoinAmount(STAGING_DEPOSIT_SAT)}.`;
      setFundingStatus(activeSession, utxos.length === 0 ? "waiting" : "error", message);
      return;
    }

    const candidates = exact;
    const previous = activeSession.stagingDeposit;
    const previouslySelected = candidates.find((candidate) =>
      candidate.txid === previous?.txid && candidate.vout === previous?.vout
    );
    const utxo = previouslySelected ?? [...candidates].sort((left, right) => {
      const txidOrder = left.txid.localeCompare(right.txid);
      return txidOrder === 0 ? left.vout - right.vout : txidOrder;
    })[0];
    const additionalDeposits = candidates.length - 1;
    const observation = {
      txid: utxo.txid,
      vout: utxo.vout,
      valueSat: utxo.value,
      confirmed: utxo.status.confirmed,
    };
    if (utxo.status.confirmed) {
      observation.blockHeight = utxo.status.block_height;
      observation.blockHash = utxo.status.block_hash;
      setFundingStatus(
        activeSession,
        "confirmed",
        `Your deposit is confirmed.${extraDepositSuffix(additionalDeposits)}`,
        observation
      );
    } else {
      setFundingStatus(
        activeSession,
        "seen",
        "Deposit received. Waiting for one confirmation…",
        observation
      );
    }
  } catch (error) {
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    fundingObservationVerified = false;
    console.error("[BP52 deposit]", error);
    const message = controller.signal.aborted
      ? "Checking your deposit again…"
      : "Couldn’t check your deposit. Retrying…";
    setFundingStatus(activeSession, "error", message);
  } finally {
    clearTimeout(timeout);
    if (fundingPollController === controller) fundingPollController = null;
  }
}

function startFundingPolling(activeSession, wallet, epoch) {
  const key = `${STAGING_DEPOSIT_SAT}/${activeSession.gameId}/${activeSession.role}/${wallet.address}`;
  if (fundingPollKey === key && fundingPollTimer) return;
  if (fundingPollTimer) clearInterval(fundingPollTimer);
  if (fundingPollController) fundingPollController.abort();
  fundingPollKey = key;
  fundingPollController = null;
  void pollStagingDeposit(activeSession, wallet, epoch);
  fundingPollTimer = setInterval(
    () => void pollStagingDeposit(activeSession, wallet, epoch),
    POLL_INTERVAL_MS
  );
}

async function ensureStagingDeposit(activeSession = session) {
  if (
    fundingPreparing || !sessionIsActive(activeSession) ||
    !activeSession.sessionNonce || activeSession.peerNonceReady !== activeSession.sessionNonce
  ) return;
  const epoch = fundingEpoch;
  const currentKey = `${STAGING_DEPOSIT_SAT}/${activeSession.gameId}/${activeSession.role}/${activeSession.stagingDeposit?.address || ""}`;
  if (fundingPollKey === currentKey && fundingPollTimer) return;
  fundingPreparing = true;
  elements["funding-card"].classList.remove("hidden");
  elements["funding-state"].className = "funding-state";
  elements["funding-state"].textContent = "Preparing your single-use deposit address…";
  try {
    const wallet = await loadOrCreateStagingWallet(activeSession, epoch);
    if (!wallet || !fundingOperationIsActive(activeSession, epoch)) return;
    renderStagingWallet(activeSession, wallet);
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    startFundingPolling(activeSession, wallet, epoch);
  } catch (error) {
    if (!fundingOperationIsActive(activeSession, epoch)) return;
    console.error("[BP52 deposit]", error);
    setFundingStatus(
      activeSession,
      "error",
      "Couldn’t prepare the deposit address. Reload to try again."
    );
  } finally {
    if (fundingEpoch === epoch) fundingPreparing = false;
  }
}

function originInputsAppearReady(activeSession) {
  return originInputsAreReady({
    expectedOriginSeen: Boolean(
      originChainObservation?.found && originPackageContext &&
      originChainObservation.txid === originPackageContext.fundingTxid
    ),
    depositObservationVerified: fundingObservationVerified,
    localDepositConfirmed: Boolean(
      activeSession?.stagingDeposit?.status === "confirmed" &&
      activeSession.stagingDeposit.confirmed === true
    ),
    framesBoundToSession: fundingFramesValidatedSession === activeSession,
    localFramePresent: Boolean(activeSession?.localStagingFunding),
    localFrameSent: Boolean(activeSession?.stagingFundingSent),
    peerFramePresent: Boolean(activeSession?.peerStagingFunding),
    peerObservationVerified: peerFundingObservationVerified,
    peerStatus: activeSession?.peerStagingFundingStatus,
    durablePackagePresent: Boolean(
      activeSession && originStateSession === activeSession && originState?.localPackagePayload
    ),
  });
}

function originSetupAuthorized(activeSession) {
  if (!activeSession || originStateSession !== activeSession || !originState) return false;
  if (!originState.setupAuthorizationPackageId || !originPackageContext) return false;
  if (originState.setupAuthorizationPackageId !== originPackageContext.packageId) {
    throw protocolError("Saved setup authorization belongs to a different origin package.");
  }
  return true;
}

function automaticSetupSnapshot(activeSession) {
  const pending = chainGameView?.pendingBroadcast;
  const pendingTxid = pending?.txid instanceof Uint8Array && pending.txid.byteLength === 32
    ? bytesToHex(pending.txid)
    : null;
  return {
    ownsSeat: ownsSeat(activeSession),
    halted: stagingExchangeHalted || Boolean(gameFlowError) || Boolean(chainGameError),
    busy: preflightAdvancing || stagingExchangeAdvancing || originAdvancing ||
      activationAuthorizing || gameTransactionBroadcasting,
    seatClaimed: Boolean(activeSession?.joined),
    localReady: Boolean(activeSession?.localReady),
    inputsReady: originInputsAppearReady(activeSession),
    packageVerified: originPackageVerified,
    packagesAgreed: originPackagesAgreed,
    localRefundPresent: Boolean(originState?.localRefundSignaturePayload),
    refundHooksAvailable: originHookAvailable("createRefundSignature") &&
      originHookAvailable("verifyAndAssembleRefund"),
    setupAuthorized: originSetupAuthorized(activeSession),
    refundVerified: originRefundVerified,
    localFundingPresent: Boolean(originState?.localFundingSignaturePayload),
    fundingHooksAvailable: originHookAvailable("createFundingSignature") &&
      originHookAvailable("verifyAndAssembleFunding"),
    fundingVerified: originFundingVerified,
    originFound: Boolean(originChainObservation?.found),
    chainFlowPresent: Boolean(chainGameFlow),
    activationReady: Boolean(chainGameView?.readyForActivation),
    activationAuthorized: Boolean(chainGameView?.activationConsent),
    originRefunded: originWasRefunded(),
    pendingPurpose: pending?.purpose,
    pendingTransactionPresent: Boolean(pending?.transaction),
    pendingTxidPresent: Boolean(pendingTxid),
    activationSubmitted: Boolean(pendingTxid && submittedGameTransactions.has(pendingTxid)),
  };
}

function scheduleAutomaticSetup(activeSession = session) {
  if (
    automaticSetupRunning || !sessionIsActive(activeSession) ||
    Date.now() < automaticSetupNextAttemptAt
  ) return;
  let action;
  try {
    action = nextAutomaticSetupAction(automaticSetupSnapshot(activeSession));
  } catch (error) {
    handleOriginActionError(activeSession, error);
    return;
  }
  if (!action) return;
  automaticSetupRunning = true;
  setTimeout(async () => {
    try {
      switch (action) {
        case AutomaticSetupAction.SEND_READY:
          await sendReady();
          break;
        case AutomaticSetupAction.PROTECT_REFUND:
          await protectOriginRefund();
          break;
        case AutomaticSetupAction.PERSIST_AUTHORIZATION:
          authorizeAutomaticSetup();
          break;
        case AutomaticSetupAction.RELEASE_FUNDING:
          await releaseOriginFundingSignature();
          break;
        case AutomaticSetupAction.BROADCAST_ORIGIN:
          await broadcastOrigin();
          break;
        case AutomaticSetupAction.AUTHORIZE_ACTIVATION:
          await authorizeGameActivation();
          break;
        case AutomaticSetupAction.BROADCAST_ACTIVATION:
          await broadcastPendingGameTransaction(0);
          break;
        default:
          throw protocolError("Automatic setup selected an unknown action.");
      }
    } catch (error) {
      handleOriginActionError(activeSession, error);
    } finally {
      automaticSetupRunning = false;
      automaticSetupNextAttemptAt = Date.now() + POLL_INTERVAL_MS;
    }
  }, 0);
}

function scheduleAutomaticGameplay(activeSession = session) {
  if (gameplayAutomationScheduled || !sessionIsActive(activeSession)) return;
  const pending = chainGameView?.pendingBroadcast;
  const recovery = chainGameView?.recovery;
  let pendingTxid = null;
  let publishAction = null;
  let automaticEdge = null;
  try {
    pendingTxid = pending?.txid ? bytesToHex(pending.txid) : null;
    if (pendingTxid !== gameplayPendingTxid) {
      gameplayPendingTxid = pendingTxid;
      gameplayPublishNextAttemptAt = 0;
    }
    const gameplayHalted = stagingExchangeHalted || Boolean(gameFlowError) || Boolean(chainGameError);
    const gameplayBusy = gameActionAuthorizing || gameTransactionBroadcasting;
    const refunded = originWasRefunded();
    publishAction = nextGameplayPublishAction({
      ownsSeat: ownsSeat(activeSession),
      halted: gameplayHalted,
      busy: gameplayBusy,
      retryReady: Date.now() >= gameplayPublishNextAttemptAt,
      originRefunded: refunded,
      pendingPurpose: pending?.purpose,
      pendingTransactionPresent: Boolean(pending?.transaction),
      pendingTxid,
      submitted: Boolean(pendingTxid && submittedGameTransactions.has(pendingTxid)),
    });
    if (
      !pending && chainGameView?.phase === GamePhase.ACTIVE && ownsSeat(activeSession) &&
      !gameplayHalted && !gameplayBusy && !refunded
    ) {
      automaticEdge = selectAutomaticGameEdge(chainGameView.legalEdges, {
        localRole: gameFlowView?.canonicalRole,
        cards: chainGameView.cards,
        authorizedChildNodeIds: automaticallyAuthorizedGameEdges,
        retryReady: Date.now() >= gameplayEdgeNextAttemptAt,
      });
    }
    if (automaticEdge && !/^[0-9a-f]{64}$/.test(bytesToHex(automaticEdge.childNodeId))) {
      throw protocolError("The automatic gameplay edge has an invalid node id.");
    }
  } catch (error) {
    const violation = error instanceof SessionProtocolError
      ? error
      : protocolError(error instanceof Error ? error.message : String(error));
    haltGameFlow(violation.message);
    showError(elements["game-error"], violation);
    return;
  }
  const publishRecovery = Boolean(
    recovery?.transaction && recoverySubmittedStep !== recovery.step &&
    !gameTransactionBroadcasting
  );
  if (!publishAction && !automaticEdge && !publishRecovery) return;

  gameplayAutomationScheduled = true;
  setTimeout(async () => {
    try {
      if (!sessionIsActive(activeSession)) return;
      if (publishRecovery) {
        await broadcastRecoveryTransaction();
      } else if (publishAction) {
        await broadcastPendingGameTransaction(1);
      } else {
        const childNodeId = bytesToHex(automaticEdge.childNodeId);
        const authorized = await authorizeGameEdgeById(childNodeId, { automatic: true });
        automaticallyAuthorizedGameEdges = recordAutomaticEdgeResult(
          automaticallyAuthorizedGameEdges,
          childNodeId,
          authorized,
        );
        if (!authorized && sessionIsActive(activeSession)) {
          const retryDelay = Math.max(0, gameplayEdgeNextAttemptAt - Date.now());
          setTimeout(() => {
            if (sessionIsActive(activeSession)) scheduleAutomaticGameplay(activeSession);
          }, retryDelay);
        }
      }
    } catch (error) {
      if (sessionIsActive(activeSession)) showError(elements["game-error"], error);
    } finally {
      if (publishAction) gameplayPublishNextAttemptAt = Date.now() + POLL_INTERVAL_MS;
      gameplayAutomationScheduled = false;
      if (sessionIsActive(activeSession)) scheduleAutomaticGameplay(activeSession);
    }
  }, 0);
}

async function loadChainAdapter() {
  if (!chainAdapterPromise) {
    chainAdapterPromise = Promise.resolve()
      .then(() => createBrowserEsploraChainAdapter(RUNTIME_CONFIG, {
        timeoutMs: RELAY_CONFIG.requestTimeoutMs,
      }))
      .catch((error) => {
        chainAdapterPromise = null;
        throw error;
      });
  }
  return chainAdapterPromise;
}

async function refreshActiveGameChain(activeSession, adapter, verifiedTip) {
  if (!gameChainRefreshReady({
    sessionActive: sessionIsActive(activeSession),
    chainFlowPresent: Boolean(chainGameFlow),
    gameFlowPresent: Boolean(gameFlow),
    gameFlowStarting: Boolean(gameFlowStarting),
    chainHalted: chainGameView?.stage === "halted",
  })) return;
  let projection = gameFlow.currentProjection();
  if (
    projection.status.phase < GamePhase.AWAITING_ACTIVATION ||
    projection.status.phase > GamePhase.SETTLED ||
    !projection.intents.some((intent) => intent.name === "observe-state")
  ) return;
  const tip = verifiedTip ?? await adapter.tip();
  if (!sessionIsActive(activeSession)) return;
  const tipKey = `${tip.block.height}/${bytesToHex(tip.block.displayHash)}`;
  if (lastGameTipKey !== tipKey) {
    try {
      chainGameView = await chainGameFlow.observeTip({ type: "tip-observed", ...tip });
    } catch (error) {
      const reason = error instanceof Error
        ? error.message
        : "The authenticated chain tip could not be applied to the game.";
      haltGameFlow(reason);
      throw protocolError(reason);
    }
    if (chainGameView?.phase === GamePhase.HALTED || chainGameView?.stage === "halted") {
      const reason = chainGameView.detail || "The authenticated chain state halted the game.";
      haltGameFlow(reason);
      throw protocolError(reason);
    }
    lastGameTipKey = tipKey;
    projection = gameFlow.currentProjection();
  }
  const observation = projection.intents.find((intent) => intent.name === "observe-state");
  if (!observation) return;
  const fact = await adapter.spendFact({
    spentOutpoint: {
      displayTxid: observation.outpoint.txid,
      vout: observation.outpoint.vout
    },
    minConfirmations: CHAIN_CONFIG.confirmations.gameplay
  });
  if (!fact || !sessionIsActive(activeSession)) return;
  const spendKey = [
    bytesToHex(fact.spentOutpoint.displayTxid),
    fact.spentOutpoint.vout,
    bytesToHex(fact.spendingDisplayTxid),
    fact.confirmedIn.height,
    bytesToHex(fact.confirmedIn.displayHash)
  ].join("/");
  if (lastConfirmedGameSpend === spendKey) return;
  try {
    chainGameView = await chainGameFlow.confirmSpend(fact);
  } catch (error) {
    const reason = error instanceof Error
      ? error.message
      : "The confirmed gameplay spend could not be verified.";
    haltGameFlow(reason);
    throw protocolError(reason);
  }
  if (chainGameView?.phase === GamePhase.HALTED || chainGameView?.stage === "halted") {
    const reason = chainGameView.detail || "The confirmed spend halted the game.";
    haltGameFlow(reason);
    throw protocolError(reason);
  }
  lastConfirmedGameSpend = spendKey;
  lastGameTipKey = `${fact.observedTip.height}/${bytesToHex(fact.observedTip.displayHash)}`;
  renderGameFlow(activeSession);
}

async function refreshOriginSafety(activeSession, packageContext, epoch) {
  if (!originOperationIsActive(activeSession, epoch) || !originChainObservation?.confirmed) return;
  const adapter = await loadChainAdapter();
  const outpoint = {
    displayTxid: hexToBytes(packageContext.fundingTxid),
    vout: packageContext.originVout
  };
  const [tip, outpointStatus] = await Promise.all([
    adapter.tip(),
    adapter.outpointStatus(outpoint)
  ]);
  if (!originOperationIsActive(activeSession, epoch)) return;
  originTipObservation = tip;
  originOutpointObservation = outpointStatus;
  if (outpointStatus.state !== "spent") {
    await refreshActiveGameChain(activeSession, adapter, tip);
    return;
  }
  const spendingTxid = bytesToHex(outpointStatus.spendingDisplayTxid);
  const refundTxid = packageContext.refundTxid;
  let activationRecoveryPending = false;
  if (!expectedActivationTxid) {
    if (!gameFlow || gameFlowStarting) {
      // A restored ACTIVE snapshot carries the authenticated activation txid in
      // its Rust projection. Do not bind the observed spender while that
      // projection is still being opened; the next bounded poll will compare
      // it after recovery.
      activationRecoveryPending = true;
    } else {
      recoverExpectedActivationTxid(activeSession, gameFlow.currentProjection());
    }
  }
  const disposition = classifyOriginSpend({
    spendingTxid,
    refundTxid,
    expectedActivationTxid,
    activationRecoveryPending,
  });
  if (disposition === OriginSpendDisposition.REFUND) {
    if (gameFlowSession === activeSession) stopGameFlow();
    return;
  }
  if (disposition === OriginSpendDisposition.RECOVERY_PENDING) return;
  if (disposition === OriginSpendDisposition.ACTIVATION) {
    await refreshActiveGameChain(activeSession, adapter, tip);
    return;
  }
  const reason = `Shared origin was spent by unexpected transaction ${spendingTxid.slice(0, 12)}….`;
  haltGameFlow(reason);
  throw protocolError(reason);
}

function stopGameFlow() {
  const current = gameFlow;
  const currentChain = chainGameFlow;
  gameFlow = null;
  gameFlowSession = null;
  gameFlowStarting = null;
  gameFlowView = null;
  gameFlowError = null;
  chainGameFlow = null;
  chainGameView = null;
  chainGameError = null;
  gameProjectionBarrierDepth = 0;
  deferredGameProjection = null;
  lastGameTipKey = null;
  lastConfirmedGameSpend = null;
  gameTransactionBroadcasting = false;
  activationAuthorizing = false;
  gameActionAuthorizing = false;
  gameplayAutomationScheduled = false;
  gameplayPublishNextAttemptAt = 0;
  gameplayEdgeNextAttemptAt = 0;
  gameplayPendingTxid = null;
  recoverySubmittedStep = null;
  automaticallyAuthorizedGameEdges.clear();
  elements["action-bar"].classList.add("hidden");
  submittedGameTransactions.clear();
  if (current) void current.cancel();
  if (currentChain) void currentChain.cancel();
}

function haltGameFlow(reason) {
  const retainedGameView = gameFlowView;
  const retainedChainView = chainGameView;
  stopGameFlow();
  gameFlowView = retainedGameView
    ? { ...retainedGameView, stage: "halted", detail: reason, error: reason }
    : null;
  chainGameView = retainedChainView
    ? { ...retainedChainView, stage: "halted", detail: reason, error: reason }
    : null;
  stagingExchangeHalted = true;
  stagingExchangeError = reason;
  gameFlowError = reason;
  chainGameError = reason;
}

function originWasRefunded() {
  return Boolean(
    originOutpointObservation?.state === "spent" && originPackageContext &&
    bytesToHex(originOutpointObservation.spendingDisplayTxid) ===
      originPackageContext.refundTxid
  );
}

const CARD_RANKS = Object.freeze(["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"]);
const CARD_SUITS = Object.freeze(["♣", "♦", "♥", "♠"]);

function renderVerifiedCard(element, cardId, placeholder) {
  const dealt = Number.isSafeInteger(cardId) && cardId >= 0 && cardId < 52;
  element.classList.toggle("empty", !dealt);
  element.classList.toggle("dealt", dealt);
  element.classList.toggle("red", dealt && [1, 2].includes(cardId % 4));
  element.textContent = dealt
    ? `${CARD_RANKS[Math.floor(cardId / 4)]}${CARD_SUITS[cardId % 4]}`
    : placeholder;
}

function localMayAuthorizeEdge(edge) {
  return Boolean(gameFlowView && chainGameView) &&
    localRoleMayAuthorizeEdge(edge, gameFlowView.canonicalRole);
}

function setActionButton(element, edge, label) {
  element.classList.toggle("hidden", !edge);
  element.disabled = !edge || !localMayAuthorizeEdge(edge) ||
    Boolean(chainGameView?.pendingBroadcast) ||
    Boolean(chainGameView?.recovery && !chainGameView.recovery.complete) ||
    gameActionAuthorizing;
  element.dataset.childNodeId = edge ? bytesToHex(edge.childNodeId) : "";
  if (edge) element.textContent = label;
}

function currentSetupFailure(primaryError = null) {
  const presentation = setupFailurePresentation({
    halted: stagingExchangeHalted || Boolean(gameFlowError) || Boolean(chainGameError),
    primaryError,
    chainGameError,
    gameFlowError,
    originError,
    stagingExchangeError,
  });
  const diagnostic = presentation?.diagnostic ?? null;
  if (diagnostic !== null && diagnostic !== lastSetupDiagnostic) {
    console.error("[BP52 setup]", diagnostic);
  }
  lastSetupDiagnostic = diagnostic;
  return presentation;
}

function setupFailureText(presentation) {
  return presentation.detail;
}

function renderSetupFailureOnTable() {
  const presentation = currentSetupFailure();
  if (!presentation) return;
  setTableStatus(presentation.headline, setupFailureText(presentation));
}

function renderTableBlinds() {
  const blinds = tableBlindView(GAME_CONFIG, gameFlowView?.canonicalRole);
  elements["table-small-blind"].textContent = blinds.smallBlind.amount;
  elements["table-big-blind"].textContent = blinds.bigBlind.amount;
  elements["funding-small-blind"].textContent = blinds.smallBlind.amount;
  elements["funding-big-blind"].textContent = blinds.bigBlind.amount;
  for (const [id, blind] of [
    ["local-blind", blinds.localBlind],
    ["opponent-blind", blinds.opponentBlind],
  ]) {
    const marker = elements[id];
    marker.classList.toggle("hidden", !blind);
    marker.textContent = blind?.badge ?? "";
    marker.setAttribute("aria-label", blind ? `${blind.name}, ${blind.amount}` : "Blind not assigned");
  }
}

function renderTableBalances() {
  renderTableBlinds();
  const balances = tableBalancesForViewer(
    gameFlowView?.tableBalances,
    gameFlowView?.canonicalRole,
    GAME_CONFIG.startingStackSat,
  );
  elements["local-stack"].textContent = `Stack · ${formatBitcoinAmount(balances.localStackSat)}`;
  elements["opponent-stack"].textContent = `Stack · ${formatBitcoinAmount(balances.opponentStackSat)}`;
  elements["game-pot"].textContent = formatBitcoinAmount(balances.potSat);
}

function renderChainGameFlow(activeSession) {
  renderTableBalances();
  const view = chainGameView;

  const pending = view?.pendingBroadcast;
  const pendingTxid = pending?.txid ? bytesToHex(pending.txid) : null;
  const pendingSubmitted = Boolean(
    pendingTxid && submittedGameTransactions.has(pendingTxid)
  );

  const cards = view?.cards;
  for (let index = 0; index < 2; index += 1) {
    renderVerifiedCard(elements[`hole-card-${index}`], cards?.localHole?.[index], "");
  }
  elements["local-hole-cards"].classList.toggle(
    "face-down", !cards?.localHole?.some((card) => card !== null)
  );
  elements["local-hole-cards"].classList.toggle(
    "face-up", Boolean(cards?.localHole?.some((card) => card !== null))
  );
  elements["local-hole-cards"].setAttribute(
    "aria-label",
    cards?.localHole?.every((card) => card !== null) ? "Verified hole cards" : "Hole cards not dealt"
  );
  for (let index = 0; index < 5; index += 1) {
    renderVerifiedCard(elements[`board-card-${index}`], cards?.board?.[index], String(index + 1));
  }

  const edges = view?.legalEdges ?? [];
  const byAction = (action) => edges.find(
    (edge) => edge.kind.name === "action" && edge.kind.action === action
  );
  setActionButton(elements["action-fold"], byAction(0), "Fold");
  setActionButton(elements["action-check"], byAction(1), "Check");
  setActionButton(elements["action-call"], byAction(2), "Call");
  const aggressive = byAction(3) ?? byAction(4);
  setActionButton(elements["action-aggressive"], aggressive, aggressive?.kind.action === 3 ? "Bet" : "Raise");
  const timeout = edges.find((edge) => edge.kind.name === "timeout");
  const matureTimeout = timeout && localMayAuthorizeEdge(timeout) &&
    Number.isSafeInteger(view?.timeoutMaturesAt) && Number.isSafeInteger(view?.tipHeight) &&
    view.tipHeight >= view.timeoutMaturesAt ? timeout : null;
  const recoveryAvailable = !view?.recovery && !pending && (
    view?.phase === GamePhase.SETTLED ||
    view?.phase === GamePhase.ACTIVE && !edges.some(
      (edge) => edge.kind.name === "action" && localMayAuthorizeEdge(edge)
    )
  );
  if (matureTimeout) {
    setActionButton(elements["action-timeout"], matureTimeout, "Claim timeout");
    elements["action-timeout"].dataset.mode = "edge";
  } else {
    elements["action-timeout"].classList.toggle("hidden", !recoveryAvailable);
    elements["action-timeout"].disabled = !recoveryAvailable || gameActionAuthorizing;
    elements["action-timeout"].dataset.childNodeId = "";
    elements["action-timeout"].dataset.mode = "recovery";
    elements["action-timeout"].textContent = "Go on-chain";
  }

  const strategicActionable = edges.some(
    (edge) => edge.kind.name === "action" && localMayAuthorizeEdge(edge)
  );
  const playerChoice = strategicActionable || Boolean(matureTimeout) || recoveryAvailable;
  const automaticEdge = selectAutomaticGameEdge(edges, {
    localRole: gameFlowView?.canonicalRole,
    cards,
  });
  elements["action-bar"].classList.toggle(
    "hidden",
    ![GamePhase.ACTIVE, GamePhase.SETTLED].includes(view?.phase) || !playerChoice,
  );
  if (view?.phase === GamePhase.ACTIVE) {
    const headline = pending?.purpose === 1
      ? pendingSubmitted ? "Waiting for confirmation" : "Sending your move…"
      : playerChoice ? "Your move" : automaticEdge ? "Continuing the game"
        : "Waiting for the opponent";
    const detail = pending?.purpose === 1 || automaticEdge
        ? "No action is needed."
        : playerChoice ? "Choose your move." : "The table will update automatically.";
    setTableStatus(headline, detail, Boolean(pending?.purpose === 1 || automaticEdge));
  } else if (view?.settlementOffchain) {
    setTableStatus("Hand complete", "The payout is agreed off-chain.");
  } else if (view?.settlement) {
    setTableStatus("Payout confirmed", "The game is complete.");
  }
  scheduleAutomaticGameplay(activeSession);
}

function renderGameFlow(activeSession) {
  const confirmed = Boolean(
    originChainObservation?.confirmed && originPackageContext &&
    originChainObservation.txid === originPackageContext.fundingTxid
  );
  const visible = confirmed || gameFlowSession === activeSession || Boolean(gameFlowView);
  const refunded = originWasRefunded();
  const failure = currentSetupFailure(gameFlowError);

  if (visible) {
    const preparingGraph = chainGameView && ![
      "ready", "active", "settled", "halted",
    ].includes(chainGameView.stage);
    const headline = refunded
      ? "Game cancelled"
      : failure ? failure.headline
      : preparingGraph || gameFlowView?.privateDealComplete
        ? "Preparing the game"
        : "Shuffling the cards";
    const detail = refunded
      ? "The funds have been returned."
      : failure
        ? setupFailureText(failure)
        : preparingGraph
          ? ""
          : "";
    setTableStatus(headline, detail, !refunded && !failure);
  }
  renderChainGameFlow(activeSession);
  renderSetupFailureOnTable();
}

async function ensureGameFlow(activeSession = session) {
  if (!sessionIsActive(activeSession) || gameFlowSession === activeSession && gameFlow) {
    return gameFlow;
  }
  if (gameFlowStarting) return gameFlowStarting;
  const refunded = originWasRefunded();
  const state = loadOriginCoordinatorState(activeSession);
  const wallet = stagingWalletContext?.activeSession === activeSession
    ? stagingWalletContext.wallet
    : null;
  if (!originGameFlowReady({
    confirmed: originChainObservation?.confirmed,
    refunded,
    packagePresent: Boolean(originPackageContext),
    refundVerified: originRefundVerified,
    signedRefundPresent: Boolean(state.signedRefundTxHex),
    walletPresent: Boolean(wallet),
    observedTxid: originChainObservation?.txid,
    fundingTxid: originPackageContext?.fundingTxid,
  })) {
    throw new Error("private setup is waiting for the exact refund-protected origin confirmation");
  }
  gameFlowStarting = (async () => {
    const chain = await loadChainAdapter();
    const feeCompatibility = await chain.relayFeeFloorCompatibility(
      CHAIN_CONFIG.feeFloorSatPerVbyte,
    );
    if (feeCompatibility.estimateAboveGraphRate) {
      console.warn(
        "[BP52 chain] Network fees exceed this table's fixed rate; publication may be delayed."
      );
    }
    if (!sessionIsActive(activeSession)) return null;
    const localXOnlyKeyHex = activeSession.localStagingFunding?.witnessScriptHex?.slice(4, 68);
    const peerXOnlyKeyHex = activeSession.peerStagingFunding?.witnessScriptHex?.slice(4, 68);
    if (
      !/^[0-9a-f]{64}$/.test(localXOnlyKeyHex || "") ||
      !/^[0-9a-f]{64}$/.test(peerXOnlyKeyHex || "") ||
      localXOnlyKeyHex === peerXOnlyKeyHex
    ) {
      throw protocolError("The confirmed origin lacks two canonical browser identity keys.");
    }
    const canonicalIdentityHexes = [localXOnlyKeyHex, peerXOnlyKeyHex].sort();
    const localRole = canonicalIdentityHexes[0] === localXOnlyKeyHex ? 0 : 1;
    const sendExchange = ({ messageId, kind, payload }) => api(
      `${RELAY_API_BASE_PATH}/games/${activeSession.gameId}/messages`,
      { method: "POST", body: JSON.stringify({ messageId, kind, payload }) },
      activeSession.playerToken
    );
    let createdChain = null;
    const created = createBrowserGameFlow({
      deploymentConfig: RUNTIME_CONFIG,
      roomId: activeSession.gameId,
      sessionNonceHex: activeSession.sessionNonce,
      transportRole: activeSession.role,
      localSecretKeyHex: wallet.privateKeyHex,
      localXOnlyKeyHex,
      peerXOnlyKeyHex,
      origin: {
        displayTxid: originPackageContext.fundingTxid,
        vout: originPackageContext.originVout,
        valueSat: originPackageContext.originValueSat,
        scriptPubkeyHex: originPackageContext.originScriptPubkeyHex,
        witnessScriptHex: originPackageContext.originWitnessScriptHex
      },
      chain,
      sendExchange,
      onUpdate: (view) => {
        if (session !== activeSession) return;
        gameFlowView = view;
        gameFlowError = view.error || null;
        renderGameFlow(activeSession);
      },
      onProjection: (projection) => {
        if (session !== activeSession) return;
        recoverExpectedActivationTxid(activeSession, projection);
        const activationBroadcast = projection.intents.find(
          (intent) => intent.name === "broadcast-transaction" && intent.purpose === 0
        );
        if (activationBroadcast?.txid) {
          rememberExpectedActivationTxid(activeSession, bytesToHex(activationBroadcast.txid));
        }
        if (createdChain) {
          if (gameProjectionBarrierDepth > 0) {
            deferredGameProjection = structuredClone(projection);
            return;
          }
          void createdChain.updateProjection(projection)
            .catch((error) => {
              if (session !== activeSession) return;
              chainGameError = error instanceof Error ? error.message : String(error);
              renderGameFlow(activeSession);
            });
        }
      }
    });
    createdChain = createBrowserChainGameFlow({
      deploymentConfig: RUNTIME_CONFIG,
      game: created,
      roomId: activeSession.gameId,
      sessionNonceHex: activeSession.sessionNonce,
      transportRole: activeSession.role,
      localRole,
      localSecretKeyHex: wallet.privateKeyHex,
      identities: canonicalIdentityHexes.map(hexToBytes),
      origin: {
        displayTxid: originPackageContext.fundingTxid,
        vout: originPackageContext.originVout,
        witnessScriptHex: originPackageContext.originWitnessScriptHex
      },
      sendExchange,
      onUpdate: (view) => {
        if (session !== activeSession) return;
        chainGameView = view;
        chainGameError = view.error || null;
        renderGameFlow(activeSession);
      }
    });
    gameFlow = created;
    chainGameFlow = createdChain;
    gameFlowSession = activeSession;
    gameFlowView = await created.start();
    recoverExpectedActivationTxid(activeSession, created.currentProjection());
    chainGameView = await createdChain.updateProjection(created.currentProjection());
    renderGameFlow(activeSession);
    return created;
  })().catch((error) => {
    if (gameFlowSession === activeSession) stopGameFlow();
    if (session === activeSession) {
      gameFlowError = error instanceof Error ? error.message : String(error);
      renderGameFlow(activeSession);
    }
    throw error;
  }).finally(() => {
    gameFlowStarting = null;
  });
  return gameFlowStarting;
}

function updateOriginUi(activeSession, nonceAgreed, bothInputsReady) {
  if (!nonceAgreed) {
    elements["broadcast-refund"].classList.add("hidden");
    return;
  }

  let state = null;
  if (ownsSeat(activeSession)) {
    try {
      state = loadOriginCoordinatorState(activeSession);
    } catch (error) {
      originError = error instanceof Error ? error.message : "Saved origin state is invalid.";
      stagingExchangeHalted = true;
      stagingExchangeError = originError;
      setRelayStatus("error", "Setup halted");
      showError(elements["game-error"], error);
    }
  }
  const localPackage = Boolean(state?.localPackagePayload);
  const peerPackage = Boolean(state?.peerPackagePayload);
  const localRefund = Boolean(state?.localRefundSignaturePayload);
  const localFunding = Boolean(state?.localFundingSignaturePayload);
  const peerFunding = Boolean(state?.peerFundingSignaturePayload);
  const setupAuthorized = originSetupAuthorized(activeSession);
  const packageCanResume = originPackageInputsReady(activeSession) || localPackage;
  const failure = currentSetupFailure(originError || stagingExchangeError);
  const playerStatus = playerSetupStatus({
    failure,
    ownsSeat: ownsSeat(activeSession),
    inputsReady: packageCanResume,
    engineAvailable: originHookAvailable("buildPackage"),
    packageVerified: originPackageVerified,
    peerPackage,
    packagesAgreed: originPackagesAgreed,
    localProtection: localRefund,
    protectionVerified: originRefundVerified,
    setupAuthorized,
    localFunding,
    peerFunding,
    fundingVerified: originFundingVerified,
    found: Boolean(originChainObservation?.found),
    confirmed: Boolean(originChainObservation?.confirmed),
  });
  if (bothInputsReady) {
    setTableStatus(playerStatus.headline, playerStatus.detail, !failure);
  }

  const originConfirmed = Boolean(originChainObservation?.confirmed);
  const tipHeight = originTipObservation?.block?.height;
  const maturityHeight = originConfirmed
    ? originChainObservation.blockHeight + ORIGIN_REFUND_CSV_BLOCKS
    : null;
  const blocksRemaining = Number.isSafeInteger(tipHeight) && maturityHeight !== null
    ? Math.max(0, maturityHeight - tipHeight)
    : null;
  const refundAvailable = Boolean(originRefundVerified && state?.signedRefundTxHex);
  const canBroadcastRefund = Boolean(
    ownsSeat(activeSession) && refundAvailable && originConfirmed && blocksRemaining === 0 &&
    originOutpointObservation?.state === "unspent" && !refundBroadcasting &&
    !stagingExchangeHalted
  );
  elements["broadcast-refund"].disabled = !canBroadcastRefund;
  elements["broadcast-refund"].classList.toggle("hidden", !canBroadcastRefund);
  elements["broadcast-refund"].textContent = "Return funds";

  if (packageCanResume) scheduleOriginCoordinator(activeSession);
}

function updateSetupUi(seatClaimed) {
  const activeSession = session;
  const localReady = Boolean(session?.localReady);
  const peerReady = Boolean(session?.peerReady);
  const bothReady = seatClaimed && localReady && peerReady;
  const nonceAgreed = Boolean(session?.sessionNonce && session?.peerNonceReady === session.sessionNonce);
  const currentFunding = fundingObservationVerified &&
    session?.stagingDeposit?.amountSat === STAGING_DEPOSIT_SAT
    ? session.stagingDeposit
    : null;
  const localDepositConfirmed = nonceAgreed && currentFunding?.status === "confirmed" &&
    currentFunding.confirmed === true;
  const fundingFramesValidated = fundingFramesValidatedSession === session;
  const localInputPublished = localDepositConfirmed && fundingFramesValidated &&
    Boolean(session?.localStagingFunding) && Boolean(session?.stagingFundingSent);
  const peerFrame = fundingFramesValidated ? session?.peerStagingFunding : null;
  const peerStatus = peerFrame ? session?.peerStagingFundingStatus : null;
  const peerInputVerified = Boolean(
    peerFrame && peerFundingObservationVerified && peerStatus === "verified"
  );
  const expectedOriginSeen = Boolean(
    originChainObservation?.found && originPackageContext &&
    originChainObservation.txid === originPackageContext.fundingTxid
  );
  const bothInputsReady = (localInputPublished && peerInputVerified) || expectedOriginSeen;

  elements["funding-local-input"].className =
    `staging-input-state${localDepositConfirmed || expectedOriginSeen ? " ready" : ""}`;
  elements["funding-local-input"].textContent = expectedOriginSeen
    ? "In the game"
    : localDepositConfirmed
    ? "Confirmed"
    : currentFunding?.status === "seen"
      ? "Waiting for confirmation"
      : "Not confirmed";
  elements["funding-peer-input"].className =
    `staging-input-state${peerInputVerified || expectedOriginSeen ? " ready" : peerFrame ? " checking" : ""}`;
  elements["funding-peer-input"].textContent = expectedOriginSeen
    ? "In the game"
    : peerInputVerified
    ? "Confirmed"
    : !peerFrame
      ? "Waiting"
      : peerStatus === "missing"
        ? "Waiting for payment"
        : peerStatus === "waiting"
          ? "Waiting for confirmation"
        : peerStatus === "error"
            ? "Checking again"
            : "Checking";
  const canFund = nonceAgreed && ownsSeat(session);
  elements["funding-card"].classList.toggle("hidden", !canFund || bothInputsReady);
  updateOriginUi(session, nonceAgreed, bothInputsReady);
  if (seatLockBlocked === "other-tab") {
    setTableStatus("Open in another tab", "Continue from the tab already using this seat.");
  } else if (seatLockBlocked === "unsupported") {
    setTableStatus("Browser not supported", "Use a browser that can keep this seat open safely.");
  } else if (!ownsSeat(session)) {
    setTableStatus("Opening your seat", "This will continue automatically.", true);
  } else if (bothReady && !nonceAgreed) {
    setTableStatus("Setting up the table", "No action is needed.", true);
  } else if (nonceAgreed && !bothInputsReady) {
    setTableStatus(
      localDepositConfirmed
        ? "Waiting for the other deposit"
        : `Fund your seat · ${formatBitcoinAmount(STAGING_DEPOSIT_SAT)}`,
      localDepositConfirmed
        ? "Your deposit is confirmed."
        : "Send the exact amount to the address shown.",
    );
  }
  if (canFund) {
    void ensureStagingDeposit(session);
    scheduleStagingFundingExchange(session);
  }
  const originConfirmed = Boolean(
    originChainObservation?.confirmed && originPackageContext &&
    originChainObservation.txid === originPackageContext.fundingTxid
  );
  const refunded = originWasRefunded();
  if (
    originConfirmed && !refunded && originRefundVerified && !stagingExchangeHalted &&
    !gameFlow && !gameFlowStarting && ownsSeat(activeSession)
  ) {
    void ensureGameFlow(activeSession).catch((error) => {
      if (session !== activeSession) return;
      gameFlowError = error instanceof Error ? error.message : String(error);
      renderGameFlow(activeSession);
    });
  }
  renderGameFlow(activeSession);
  scheduleAutomaticSetup(activeSession);
}

async function poll() {
  if (!session || polling || stagingExchangeHalted) return;
  const activeSession = session;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  pollController = controller;
  polling = true;
  try {
    const status = await api(
      `${RELAY_API_BASE_PATH}/games/${activeSession.gameId}`,
      { signal: controller.signal },
      activeSession.playerToken
    );
    if (session !== activeSession) return;
    const seatClaimed = Boolean(status.joined);
    activeSession.joined = seatClaimed;
    if (stagingExchangeHalted) {
      setRelayStatus("error", "Setup halted");
    } else {
      setRelayStatus("ready", "Connected");
      clearError(elements["game-error"]);
    }
    elements["opponent-state"].textContent = seatClaimed ? "Seat claimed" : "Waiting to join";
    setTableStatus(
      seatClaimed ? "Both seats claimed" : "Waiting for opponent",
      seatClaimed ? "The game will begin automatically." : "Share the private link to fill the table.",
      seatClaimed,
    );
    if (seatClaimed) elements["invite-card"].classList.add("hidden");
    updateSetupUi(seatClaimed);

    const messages = await api(
      `${RELAY_API_BASE_PATH}/games/${activeSession.gameId}/messages?after=${activeSession.cursor || 0}&limit=16`,
      { signal: controller.signal },
      activeSession.playerToken
    );
    if (session !== activeSession) return;
    const page = Array.isArray(messages.messages) ? messages.messages : [];
    let observedCursor = activeSession.cursor || 0;
    let deferredCursor = null;
    for (const message of page) {
      validateRelayMessage(message, observedCursor);
      const applied = await applySessionMessage(activeSession, message);
      if (session !== activeSession) return;
      if (applied === false) {
        deferredCursor = message.cursor;
        break;
      }
      console.debug("[BP52 relay]", {
        cursor: message.cursor,
        sender: message.sender === activeSession.role ? "local" : "peer",
        kind: message.kind,
      });
      observedCursor = message.cursor;
    }
    if (
      !Number.isSafeInteger(messages.nextCursor) ||
      (deferredCursor === null && messages.nextCursor !== observedCursor) ||
      (deferredCursor !== null && messages.nextCursor < deferredCursor)
    ) {
      throw protocolError("Relay returned an inconsistent message cursor.");
    }
    activeSession.cursor = observedCursor;
    saveSession(activeSession);
    await advanceSessionPreflight(activeSession);
    if (session !== activeSession) return;
    updateSetupUi(seatClaimed);
  } catch (error) {
    if (session !== activeSession) return;
    const timedOut = controller.signal.aborted;
    if (error instanceof SessionProtocolError) {
      stagingExchangeHalted = true;
      stagingExchangeError = error.message;
    }
    setRelayStatus(
      "error",
      error instanceof SessionProtocolError ? "Setup halted" : "Connection unavailable"
    );
    showError(
      elements["game-error"],
      timedOut ? new Error("Relay request timed out.") : error
    );
  } finally {
    clearTimeout(timeout);
    if (pollController === controller) pollController = null;
    polling = false;
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  setRelayStatus("connecting", "Connecting");
  void poll();
  pollTimer = setInterval(() => void poll(), POLL_INTERVAL_MS);
}

async function applySessionMessage(activeSession, message) {
  const fromLocalPlayer = message.sender === activeSession.role;
  if (message.kind === GAME_EXCHANGE_KIND || message.kind === CHAIN_EXCHANGE_KIND) {
    const originState = loadOriginCoordinatorState(activeSession);
    const originReady = originGameFlowReady({
      confirmed: originChainObservation?.confirmed,
      refunded: originWasRefunded(),
      packagePresent: Boolean(originPackageContext),
      refundVerified: originRefundVerified,
      signedRefundPresent: Boolean(originState.signedRefundTxHex),
      walletPresent: Boolean(
        stagingWalletContext?.activeSession === activeSession && stagingWalletContext.wallet
      ),
      observedTxid: originChainObservation?.txid,
      fundingTxid: originPackageContext?.fundingTxid,
    });
    if (!originReady) {
      scheduleAutomaticSetup(activeSession);
      return false;
    }
  }
  if (message.kind === GAME_EXCHANGE_KIND) {
    if (originWasRefunded()) return;
    const coordinator = await ensureGameFlow(activeSession);
    if (!coordinator || session !== activeSession) return;
    gameProjectionBarrierDepth += 1;
    try {
      // Persist the opaque frame before the secret CHAIN Worker touches it.
      // A crash at any later point can safely replay from this exact binding.
      await coordinator.stageRelayMessage(message);
      const chainAcceptance = chainGameFlow && session === activeSession
        ? await chainGameFlow.acceptGameRelayMessage(message)
        : null;
      if (chainAcceptance?.disposition !== "verified-receipt") {
        await coordinator.acceptRelayMessage(message, {
          chainCheckpointReceipt: chainAcceptance?.checkpointReceipt,
        });
      }
    } finally {
      gameProjectionBarrierDepth -= 1;
    }
    if (chainGameFlow && session === activeSession) {
      const projection = deferredGameProjection ?? coordinator.currentProjection();
      deferredGameProjection = null;
      await chainGameFlow.updateProjection(projection);
    }
    return;
  }
  if (message.kind === CHAIN_EXCHANGE_KIND) {
    if (originWasRefunded()) return;
    await ensureGameFlow(activeSession);
    if (!chainGameFlow || session !== activeSession) return;
    const result = await chainGameFlow.acceptChainRelayMessage(message);
    return result.deferred ? false : undefined;
  }
  if (
    [
      ORIGIN_PACKAGE_KIND,
      ORIGIN_REFUND_SIGNATURE_KIND,
      ORIGIN_FUNDING_SIGNATURE_KIND
    ].includes(message.kind) &&
    (!activeSession.sessionNonce || activeSession.peerNonceReady !== activeSession.sessionNonce)
  ) {
    throw protocolError("Origin metadata arrived before session nonce agreement.");
  }
  if (message.kind === READY_MESSAGE_KIND) {
    if (message.payload !== READY_MESSAGE_PAYLOAD) {
      throw protocolError("Peer sent an invalid setup-readiness message.");
    }
    if (fromLocalPlayer) activeSession.localReady = true;
    else activeSession.peerReady = true;
    return;
  }

  if (message.kind === NONCE_COMMIT_KIND) {
    const commitment = bytesToHex(decodeFixedBase64(message.payload, 32));
    const field = fromLocalPlayer ? "localNonceCommit" : "peerNonceCommit";
    if (activeSession[field] && activeSession[field] !== commitment) {
      throw protocolError("A player sent conflicting session commitments.");
    }
    activeSession[field] = commitment;
    return;
  }

  if (message.kind === NONCE_REVEAL_KIND) {
    const share = decodeFixedBase64(message.payload, 32);
    const shareHex = bytesToHex(share);
    if (fromLocalPlayer) {
      if (!activeSession.localNonceCommit) {
        throw protocolError("Local session randomness was revealed before its commitment.");
      }
      const expected = await nonceCommitment(message.sender, activeSession.gameId, share);
      if (session !== activeSession) return;
      if (bytesToHex(expected) !== activeSession.localNonceCommit) {
        throw protocolError("The replayed local session reveal does not match its commitment.");
      }
      if (activeSession.nonceShare && activeSession.nonceShare !== shareHex) {
        throw protocolError("The local session reveal does not match saved state.");
      }
      activeSession.nonceShare = shareHex;
      return;
    }
    if (!activeSession.peerNonceCommit) {
      throw protocolError("Peer revealed session randomness before committing to it.");
    }
    const expected = await nonceCommitment(message.sender, activeSession.gameId, share);
    if (session !== activeSession) return;
    if (bytesToHex(expected) !== activeSession.peerNonceCommit) {
      throw protocolError("Peer session randomness does not match its commitment.");
    }
    if (activeSession.peerNonceShare && activeSession.peerNonceShare !== shareHex) {
      throw protocolError("Peer sent conflicting session randomness.");
    }
    activeSession.peerNonceShare = shareHex;
    return;
  }

  if (message.kind === NONCE_READY_KIND) {
    const nonce = bytesToHex(decodeFixedBase64(message.payload, 32));
    if (activeSession.sessionNonce && nonce !== activeSession.sessionNonce) {
      throw protocolError("Players derived different session nonces.");
    }
    if (!fromLocalPlayer) activeSession.peerNonceReady = nonce;
    return;
  }

  if (message.kind === STAGING_FUNDING_KIND) {
    const artifact = relayOriginArtifact(message.payload);
    if (fromLocalPlayer) {
      if (
        !activeSession.stagingFundingPayload ||
        activeSession.stagingFundingPayload !== artifact
      ) {
        throw protocolError("Relay returned an unexpected local staging-input frame.");
      }
      return;
    }
    try {
      activeSession.peerStagingFundingPayload = acceptOpaqueRelayArtifact(
        activeSession.peerStagingFundingPayload,
        artifact,
        MAX_RELAY_PAYLOAD_BASE64_BYTES,
      );
    } catch (_) {
      throw protocolError("Opponent sent conflicting staging-input metadata.");
    }
    activeSession.peerStagingFundingStatus = "pending";
    activeSession.peerStagingFundingObservation = null;
    peerFundingObservationVerified = false;
    peerFundingNextCheckAt = 0;
    originPackageVerified = false;
    originPackagesAgreed = false;
    saveSession(activeSession);
    return;
  }

  if (message.kind === ORIGIN_PACKAGE_KIND) {
    const artifact = relayOriginArtifact(message.payload);
    const state = loadOriginCoordinatorState(activeSession);
    if (fromLocalPlayer) {
      if (
        state.localPackageMessageId !== message.messageId ||
        state.localPackagePayload !== artifact
      ) {
        throw protocolError("Relay returned an unexpected local origin-package frame.");
      }
      return;
    }
    try {
      state.peerPackagePayload = acceptOpaqueRelayArtifact(
        state.peerPackagePayload,
        artifact,
        MAX_RELAY_PAYLOAD_BASE64_BYTES,
      );
    } catch (_) {
      throw protocolError("Opponent sent conflicting origin-package metadata.");
    }
    saveOriginCoordinatorState(activeSession);
    originPackagesAgreed = false;
    return;
  }

  if (
    message.kind === ORIGIN_REFUND_SIGNATURE_KIND ||
    message.kind === ORIGIN_FUNDING_SIGNATURE_KIND
  ) {
    const isFunding = message.kind === ORIGIN_FUNDING_SIGNATURE_KIND;
    const artifact = relayOriginArtifact(message.payload);
    const state = loadOriginCoordinatorState(activeSession);
    if (!state.localPackagePayload || !state.peerPackagePayload) {
      throw protocolError("Origin signature arrived before package agreement.");
    }
    if (isFunding) {
      if (!state.localRefundSignaturePayload || !state.peerRefundSignaturePayload) {
        throw protocolError("Funding signature arrived before both refund signatures.");
      }
    }
    const prefix = isFunding ? "localFundingSignature" : "localRefundSignature";
    const peerField = isFunding
      ? "peerFundingSignaturePayload"
      : "peerRefundSignaturePayload";
    if (fromLocalPlayer) {
      if (
        state[`${prefix}MessageId`] !== message.messageId ||
        state[`${prefix}Payload`] !== artifact
      ) {
        throw protocolError("Relay returned an unexpected local origin-signature frame.");
      }
      return;
    }
    try {
      state[peerField] = acceptOpaqueRelayArtifact(
        state[peerField],
        artifact,
        MAX_RELAY_PAYLOAD_BASE64_BYTES,
      );
    } catch (_) {
      throw protocolError("Opponent sent conflicting origin-signature metadata.");
    }
    saveOriginCoordinatorState(activeSession);
    if (isFunding) originFundingVerified = false;
    else {
      originRefundVerified = false;
      originFundingVerified = false;
    }
    return;
  }

}

function validateRelayMessage(message, previousCursor) {
  if (
    !message || !Number.isSafeInteger(message.cursor) || message.cursor !== previousCursor + 1 ||
    !/^[0-9a-f]{64}$/.test(message.messageId || "") ||
    (message.sender !== "alice" && message.sender !== "bob") ||
    !/^[a-z0-9][a-z0-9._-]{0,31}$/.test(message.kind || "") ||
    typeof message.payload !== "string"
  ) {
    throw protocolError("Relay returned malformed message metadata.");
  }
}

async function sendStableSessionFrame(activeSession, prefix, kind, payload) {
  if (!sessionIsActive(activeSession)) return false;
  const idField = `${prefix}MessageId`;
  const payloadField = `${prefix}Payload`;
  const sentField = `${prefix}Sent`;
  if (activeSession[sentField]) return true;
  if (activeSession[payloadField] && activeSession[payloadField] !== payload) {
    throw protocolError("Saved session outbox conflicts with the current setup state.");
  }
  activeSession[idField] ||= randomHex(32);
  activeSession[payloadField] = payload;
  saveSession(activeSession);
  await api(`${RELAY_API_BASE_PATH}/games/${activeSession.gameId}/messages`, {
    method: "POST",
    body: JSON.stringify({ messageId: activeSession[idField], kind, payload })
  }, activeSession.playerToken);
  if (!sessionIsActive(activeSession)) return false;
  activeSession[sentField] = true;
  saveSession(activeSession);
  return true;
}

async function advanceSessionPreflight(activeSession = session) {
  if (
    preflightAdvancing || !sessionIsActive(activeSession) || !activeSession.joined ||
    !activeSession.localReady || !activeSession.peerReady ||
    (activeSession.sessionNonce && activeSession.peerNonceReady === activeSession.sessionNonce)
  ) return;
  preflightAdvancing = true;
  try {
    // A recovery import may intentionally restart relay replay from cursor zero.
    // Once a commitment exists, its missing preimage must come from the already
    // posted local reveal; generating a replacement would necessarily conflict.
    if (!activeSession.nonceShare && activeSession.localNonceCommit) return;
    activeSession.nonceShare ||= randomHex(32);
    const localShare = hexToBytes(activeSession.nonceShare);
    const localCommitment = await nonceCommitment(
      activeSession.role,
      activeSession.gameId,
      localShare
    );
    if (!sessionIsActive(activeSession)) return;
    const localCommitmentHex = bytesToHex(localCommitment);
    if (
      activeSession.localNonceCommit &&
      activeSession.localNonceCommit !== localCommitmentHex
    ) {
      throw protocolError("Saved session randomness does not match its commitment.");
    }
    activeSession.localNonceCommit = localCommitmentHex;
    saveSession(activeSession);
    if (!await sendStableSessionFrame(
      activeSession,
      "nonceCommit",
      NONCE_COMMIT_KIND,
      encodeBase64Bytes(localCommitment)
    )) return;

    if (!activeSession.peerNonceCommit) return;
    if (!await sendStableSessionFrame(
      activeSession,
      "nonceReveal",
      NONCE_REVEAL_KIND,
      encodeBase64Bytes(localShare)
    )) return;

    if (!activeSession.peerNonceShare) return;
    const peerShare = hexToBytes(activeSession.peerNonceShare);
    const hostShare = activeSession.role === "alice" ? localShare : peerShare;
    const guestShare = activeSession.role === "bob" ? localShare : peerShare;
    const nonce = await deriveSessionNonce(activeSession.gameId, hostShare, guestShare);
    if (!sessionIsActive(activeSession)) return;
    const nonceHex = bytesToHex(nonce);
    if (activeSession.sessionNonce && activeSession.sessionNonce !== nonceHex) {
      throw protocolError("Saved and derived session nonces do not match.");
    }
    if (activeSession.peerNonceReady && activeSession.peerNonceReady !== nonceHex) {
      throw protocolError("Players derived different session nonces.");
    }
    activeSession.sessionNonce = nonceHex;
    saveSession(activeSession);
    await sendStableSessionFrame(
      activeSession,
      "nonceReady",
      NONCE_READY_KIND,
      encodeBase64Bytes(nonce)
    );
  } finally {
    preflightAdvancing = false;
  }
}

function localOriginSecretKey(activeSession) {
  const context = stagingWalletContext;
  if (
    !context || context.activeSession !== activeSession ||
    context.wallet.witnessScriptHex !== activeSession.localStagingFunding?.witnessScriptHex ||
    !/^[0-9a-f]{64}$/.test(context.wallet.privateKeyHex || "")
  ) {
    throw protocolError("The active local staging key does not match the origin input.");
  }
  return context.wallet.privateKeyHex;
}

function originSignatureFromHook(result) {
  return hookOriginArtifact(result, "signatureFrame");
}

function handleOriginActionError(activeSession, error) {
  if (!sessionIsActive(activeSession)) return;
  originError = error instanceof Error ? error.message : "Origin action failed.";
  if (error instanceof SessionProtocolError) {
    stagingExchangeHalted = true;
    stagingExchangeError = originError;
    setRelayStatus("error", "Setup halted");
  }
  showError(elements["game-error"], error);
}

function authorizeAutomaticSetup() {
  const activeSession = session;
  if (
    !sessionIsActive(activeSession) || !originPackageVerified || !originPackagesAgreed ||
    !originPackageContext || !originRefundVerified || stagingExchangeHalted
  ) return;
  clearError(elements["game-error"]);
  try {
    const state = readBackOriginCoordinatorState(activeSession);
    const agreed = agreedOriginPackage(activeSession, state);
    const packageId = agreedOriginPackageId(agreed);
    const signatures = storedOriginSignatures(state);
    if (!signatures.localRefund || !signatures.peerRefund || !state.signedRefundTxHex) {
      throw protocolError("Automatic authorization requires the durable verified refund.");
    }
    if (
      state.setupAuthorizationPackageId &&
      state.setupAuthorizationPackageId !== packageId
    ) {
      throw protocolError("Saved setup authorization belongs to a different origin package.");
    }
    state.setupAuthorizationPackageId = packageId;
    saveOriginCoordinatorState(activeSession);
    const persisted = readBackOriginCoordinatorState(activeSession);
    if (persisted.setupAuthorizationPackageId !== packageId) {
      throw protocolError("Start-game authorization failed its durable read-back check.");
    }
    originError = null;
    automaticSetupNextAttemptAt = 0;
  } catch (error) {
    handleOriginActionError(activeSession, error);
  }
  if (sessionIsActive(activeSession)) updateSetupUi(Boolean(activeSession.joined));
}

async function protectOriginRefund() {
  const activeSession = session;
  if (
    originAdvancing || !sessionIsActive(activeSession) || !originPackageVerified ||
    !originPackagesAgreed || !originPackageContext || !originInputsAppearReady(activeSession)
  ) return;
  const epoch = originEpoch;
  originAdvancing = true;
  clearError(elements["game-error"]);
  try {
    let state = loadOriginCoordinatorState(activeSession);
    agreedOriginPackage(activeSession, state);
    if (state.localRefundSignaturePayload) return;
    if (!await freshlyVerifyOriginInputs(activeSession, epoch)) return;
    const payload = originSignatureFromHook(
      await callOriginHook("createRefundSignature", {
        ...originPackageContext.boundInput,
        sighashHex: originPackageContext.refundSighashHex,
        localSecretKeyHex: localOriginSecretKey(activeSession)
      })
    );
    if (!originOperationIsActive(activeSession, epoch)) return;
    await sendStableOriginFrame(
      activeSession,
      "localRefundSignature",
      ORIGIN_REFUND_SIGNATURE_KIND,
      payload
    );
    if (!originOperationIsActive(activeSession, epoch)) return;
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    state = loadOriginCoordinatorState(activeSession);
    if (state.signedRefundTxHex) {
      const persisted = readBackOriginCoordinatorState(activeSession);
      if (persisted.signedRefundTxHex !== state.signedRefundTxHex) {
        throw protocolError("Refund recovery failed its durable read-back check.");
      }
      await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    }
    originError = null;
  } catch (error) {
    handleOriginActionError(activeSession, error);
  } finally {
    if (originEpoch === epoch) originAdvancing = false;
    if (sessionIsActive(activeSession)) updateSetupUi(Boolean(activeSession.joined));
  }
}

async function releaseOriginFundingSignature() {
  const activeSession = session;
  if (
    originAdvancing || !sessionIsActive(activeSession) || !originPackageVerified ||
    !originPackagesAgreed || !originPackageContext || !originRefundVerified ||
    !originInputsAppearReady(activeSession) || !originSetupAuthorized(activeSession)
  ) return;
  const epoch = originEpoch;
  originAdvancing = true;
  clearError(elements["game-error"]);
  try {
    let state = readBackOriginCoordinatorState(activeSession);
    if (state.localFundingSignaturePayload) return;
    agreedOriginPackage(activeSession, state);
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    if (!originOperationIsActive(activeSession, epoch) || !originRefundVerified) {
      throw protocolError("The durable fully signed refund could not be revalidated.");
    }
    state = readBackOriginCoordinatorState(activeSession);
    if (!state.signedRefundTxHex) {
      throw protocolError("The fully signed refund is not durably available.");
    }
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    if (!originRefundVerified) {
      throw protocolError("The refund failed its final pre-authorization check.");
    }
    if (!await freshlyVerifyOriginInputs(activeSession, epoch)) return;
    const signatures = storedOriginSignatures(state);
    if (!signatures.localRefund || !signatures.peerRefund) {
      throw protocolError("Both verified refund shares are required before funding authorization.");
    }
    const sighashHex = originPackageContext.fundingSighashesHex[
      originPackageContext.localInputIndex
    ];
    const payload = originSignatureFromHook(
      await callOriginHook("createFundingSignature", {
        ...originPackageContext.boundInput,
        sighashHex,
        ...durableRefundArtifacts(state, MAX_RELAY_PAYLOAD_BASE64_BYTES),
        localSecretKeyHex: localOriginSecretKey(activeSession)
      })
    );
    if (!originOperationIsActive(activeSession, epoch)) return;
    await sendStableOriginFrame(
      activeSession,
      "localFundingSignature",
      ORIGIN_FUNDING_SIGNATURE_KIND,
      payload
    );
    if (!originOperationIsActive(activeSession, epoch)) return;
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    originError = null;
  } catch (error) {
    handleOriginActionError(activeSession, error);
  } finally {
    if (originEpoch === epoch) originAdvancing = false;
    if (sessionIsActive(activeSession)) updateSetupUi(Boolean(activeSession.joined));
  }
}

async function submitOriginFundingTransaction(activeSession, rawTxHex, expectedTxid, epoch) {
  try {
    const adapter = await loadChainAdapter();
    const result = await adapter.publish(hexToBytes(rawTxHex), {
      expectedProfileId: hexToBytes(CHAIN_NETWORK_ID_HEX),
    });
    if (!originOperationIsActive(activeSession, epoch)) return null;
    const txid = bytesToHex(result);
    if (txid !== expectedTxid) {
      throw protocolError("The chain backend returned an unexpected origin transaction id.");
    }
    return txid;
  } catch (error) {
    const observed = await pollOriginChainStatus(
      activeSession,
      originPackageContext,
      epoch,
      true,
    );
    if (observed?.found && observed.txid === expectedTxid) return expectedTxid;
    throw error;
  }
}

async function broadcastOrigin() {
  const activeSession = session;
  if (
    originAdvancing || !sessionIsActive(activeSession) || !originPackageVerified ||
    !originPackagesAgreed || !originPackageContext || !originFundingVerified ||
    !originSetupAuthorized(activeSession)
  ) return;
  const epoch = originEpoch;
  originAdvancing = true;
  clearError(elements["game-error"]);
  try {
    let state = readBackOriginCoordinatorState(activeSession);
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    if (!originOperationIsActive(activeSession, epoch) || !originFundingVerified) {
      throw protocolError("The fully signed funding transaction could not be revalidated.");
    }
    state = readBackOriginCoordinatorState(activeSession);
    if (!state.signedFundingTxHex) {
      throw protocolError("The fully signed funding transaction is not durably available.");
    }
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    if (!originFundingVerified) {
      throw protocolError("Funding transaction failed its final broadcast check.");
    }
    const observed = await pollOriginChainStatus(
      activeSession,
      originPackageContext,
      epoch,
      true
    );
    const shouldPublish = await originPublicationRequired(
      observed,
      () => freshlyVerifyOriginInputs(activeSession, epoch),
      () => pollOriginChainStatus(activeSession, originPackageContext, epoch, true),
    );
    if (shouldPublish) {
      await submitOriginFundingTransaction(
        activeSession,
        state.signedFundingTxHex,
        originPackageContext.fundingTxid,
        epoch
      );
    }
    if (!originOperationIsActive(activeSession, epoch)) return;
    originChainNextCheckAt = 0;
    await pollOriginChainStatus(activeSession, originPackageContext, epoch, true);
    originError = null;
  } catch (error) {
    handleOriginActionError(activeSession, error);
  } finally {
    if (originEpoch === epoch) originAdvancing = false;
    if (sessionIsActive(activeSession)) updateSetupUi(Boolean(activeSession.joined));
  }
}

async function broadcastAbortRefund() {
  const activeSession = session;
  if (
    refundBroadcasting || !sessionIsActive(activeSession) || !originPackageContext ||
    !originRefundVerified || !originChainObservation?.confirmed
  ) return;
  refundBroadcasting = true;
  setBusy(elements["broadcast-refund"], true);
  clearError(elements["game-error"]);
  const epoch = originEpoch;
  try {
    await reconcileOriginArtifacts(activeSession, originPackageContext, epoch);
    if (!originOperationIsActive(activeSession, epoch) || !originRefundVerified) {
      throw protocolError("The signed abort refund could not be revalidated.");
    }
    const state = readBackOriginCoordinatorState(activeSession);
    if (!state.signedRefundTxHex) {
      throw protocolError("The signed abort refund is not durably available.");
    }
    await refreshOriginSafety(activeSession, originPackageContext, epoch);
    const maturityHeight = originChainObservation.blockHeight + ORIGIN_REFUND_CSV_BLOCKS;
    if (
      originOutpointObservation?.state !== "unspent" ||
      !Number.isSafeInteger(originTipObservation?.block?.height) ||
      originTipObservation.block.height < maturityHeight
    ) {
      throw new Error("The abort refund is not mature on the independently checked chain tip.");
    }
    const adapter = await loadChainAdapter();
    try {
      const txid = await adapter.publish(hexToBytes(state.signedRefundTxHex), {
        expectedProfileId: hexToBytes(CHAIN_NETWORK_ID_HEX)
      });
      if (bytesToHex(txid) !== originPackageContext.refundTxid) {
        throw protocolError("The chain backend returned a different abort-refund transaction id.");
      }
    } catch (error) {
      const status = await adapter.outpointStatus({
        displayTxid: hexToBytes(originPackageContext.fundingTxid),
        vout: originPackageContext.originVout
      });
      if (
        status.state !== "spent" ||
        bytesToHex(status.spendingDisplayTxid) !== originPackageContext.refundTxid
      ) throw error;
      originOutpointObservation = status;
    }
    if (gameFlow) await gameFlow.cancel();
    gameFlowError = "Abort refund broadcast; game setup stopped.";
    originChainNextCheckAt = 0;
    await pollOriginChainStatus(activeSession, originPackageContext, epoch, true);
  } catch (error) {
    if (session === activeSession) showError(elements["game-error"], error);
  } finally {
    refundBroadcasting = false;
    if (session === activeSession) {
      setBusy(elements["broadcast-refund"], false);
      updateSetupUi(Boolean(activeSession.joined));
    }
  }
}

async function authorizeGameActivation() {
  const activeSession = session;
  if (
    activationAuthorizing || !sessionIsActive(activeSession) || !chainGameFlow ||
    !chainGameView?.readyForActivation || chainGameView.activationConsent || originWasRefunded() ||
    !originSetupAuthorized(activeSession)
  ) return;
  activationAuthorizing = true;
  clearError(elements["game-error"]);
  renderGameFlow(activeSession);
  try {
    chainGameView = await chainGameFlow.authorizeActivation();
  } catch (error) {
    if (session === activeSession) {
      chainGameError = error instanceof Error ? error.message : String(error);
      showError(elements["game-error"], error);
    }
  } finally {
    activationAuthorizing = false;
    if (session === activeSession) renderGameFlow(activeSession);
  }
}

async function authorizeGameEdgeById(childNodeId, { automatic = false } = {}) {
  const activeSession = session;
  if (
    gameActionAuthorizing || !sessionIsActive(activeSession) || !chainGameFlow ||
    !/^[0-9a-f]{64}$/.test(childNodeId || "")
  ) return false;
  gameActionAuthorizing = true;
  clearError(elements["game-error"]);
  renderGameFlow(activeSession);
  try {
    chainGameView = await chainGameFlow.authorizeEdge(childNodeId);
    gameplayPublishNextAttemptAt = 0;
    if (automatic) gameplayEdgeNextAttemptAt = 0;
    return true;
  } catch (error) {
    if (session === activeSession) {
      if (automatic) {
        gameplayEdgeNextAttemptAt = Date.now() + POLL_INTERVAL_MS;
        console.error("[BP52 automatic game transition]", error);
      } else {
        chainGameError = error instanceof Error ? error.message : String(error);
        showError(elements["game-error"], error);
      }
    }
    return false;
  } finally {
    gameActionAuthorizing = false;
    if (session === activeSession) renderGameFlow(activeSession);
  }
}

async function authorizeGameEdge(button) {
  if (button.disabled) return false;
  if (button.dataset.mode === "recovery") {
    const activeSession = session;
    if (gameActionAuthorizing || !sessionIsActive(activeSession) || !chainGameFlow) return false;
    gameActionAuthorizing = true;
    clearError(elements["game-error"]);
    renderGameFlow(activeSession);
    try {
      chainGameView = await chainGameFlow.recoverOnchain();
      scheduleAutomaticGameplay(activeSession);
      return true;
    } catch (error) {
      if (session === activeSession) {
        chainGameError = error instanceof Error ? error.message : String(error);
        showError(elements["game-error"], error);
      }
      return false;
    } finally {
      gameActionAuthorizing = false;
      if (session === activeSession) renderGameFlow(activeSession);
    }
  }
  return authorizeGameEdgeById(button.dataset.childNodeId);
}

async function broadcastRecoveryTransaction() {
  const activeSession = session;
  const recovery = chainGameView?.recovery;
  if (
    gameTransactionBroadcasting || !sessionIsActive(activeSession) ||
    !recovery?.transaction || recoverySubmittedStep === recovery.step || originWasRefunded()
  ) return;
  gameTransactionBroadcasting = true;
  clearError(elements["game-error"]);
  renderGameFlow(activeSession);
  try {
    const adapter = await loadChainAdapter();
    const submittedTxid = await adapter.publish(recovery.transaction, {
      expectedProfileId: hexToBytes(CHAIN_NETWORK_ID_HEX)
    });
    if (!sessionIsActive(activeSession)) return;
    submittedGameTransactions.add(bytesToHex(submittedTxid));
    recoverySubmittedStep = recovery.step;
    originChainNextCheckAt = 0;
    if (originPackageContext) {
      await pollOriginChainStatus(activeSession, originPackageContext, originEpoch, true);
    }
  } catch (error) {
    if (session === activeSession) showError(elements["game-error"], error);
  } finally {
    gameTransactionBroadcasting = false;
    if (session === activeSession) renderGameFlow(activeSession);
  }
}

async function broadcastPendingGameTransaction(expectedPurpose = null) {
  const activeSession = session;
  const pending = chainGameView?.pendingBroadcast;
  if (
    gameTransactionBroadcasting || !sessionIsActive(activeSession) || !pending?.transaction ||
    !pending.txid || originWasRefunded() ||
    (expectedPurpose !== null && pending.purpose !== expectedPurpose) ||
    (pending.purpose === 0 && !originSetupAuthorized(activeSession))
  ) return;
  const expectedTxid = bytesToHex(pending.txid);
  if (submittedGameTransactions.has(expectedTxid)) return;
  gameTransactionBroadcasting = true;
  clearError(elements["game-error"]);
  renderGameFlow(activeSession);
  try {
    const adapter = await loadChainAdapter();
    let accepted = false;
    try {
      const submittedTxid = await adapter.publish(pending.transaction, {
        expectedProfileId: hexToBytes(CHAIN_NETWORK_ID_HEX)
      });
      if (bytesToHex(submittedTxid) !== expectedTxid) {
        throw protocolError("The chain backend returned a different game transaction id.");
      }
      accepted = true;
    } catch (error) {
      const projection = gameFlow?.currentProjection();
      const observation = projection?.intents.find((intent) => intent.name === "observe-state");
      if (observation) {
        const status = await adapter.outpointStatus({
          displayTxid: observation.outpoint.txid,
          vout: observation.outpoint.vout
        });
        accepted = status.state === "spent" &&
          bytesToHex(status.spendingDisplayTxid) === expectedTxid;
      }
      if (!accepted) throw error;
    }
    if (!sessionIsActive(activeSession)) return;
    submittedGameTransactions.add(expectedTxid);
    if (pending.purpose === 0) {
      rememberExpectedActivationTxid(activeSession, expectedTxid);
    }
    originChainNextCheckAt = 0;
    if (originPackageContext) {
      await pollOriginChainStatus(activeSession, originPackageContext, originEpoch, true);
    }
  } catch (error) {
    if (session === activeSession) showError(elements["game-error"], error);
  } finally {
    gameTransactionBroadcasting = false;
    if (session === activeSession) renderGameFlow(activeSession);
  }
}

async function sendReady() {
  const activeSession = session;
  if (
    !sessionIsActive(activeSession) || !activeSession.joined || activeSession.localReady
  ) return;
  const messageId = activeSession.readyMessageId || randomHex(32);
  activeSession.readyMessageId = messageId;
  saveSession(activeSession);
  clearError(elements["game-error"]);
  try {
    await api(`${RELAY_API_BASE_PATH}/games/${activeSession.gameId}/messages`, {
      method: "POST",
      body: JSON.stringify({
        messageId,
        kind: READY_MESSAGE_KIND,
        payload: READY_MESSAGE_PAYLOAD
      })
    }, activeSession.playerToken);
    if (!sessionIsActive(activeSession)) return;
    activeSession.localReady = true;
    saveSession(activeSession);
    updateSetupUi(true);
    await advanceSessionPreflight(activeSession);
    if (session !== activeSession) return;
    await poll();
  } catch (error) {
    if (session !== activeSession) return;
    if (error instanceof SessionProtocolError) {
      setRelayStatus("error", "Setup halted");
    }
    showError(elements["game-error"], error);
  } finally {
    if (session === activeSession) updateSetupUi(Boolean(activeSession.joined));
  }
}

elements["create-tab"].addEventListener("click", () => selectTab("create"));
elements["join-tab"].addEventListener("click", () => selectTab("join"));
elements["create-game"].addEventListener("click", () => void createGame());
elements["join-game"].addEventListener("click", () => void joinGame());
elements["broadcast-refund"].addEventListener("click", () => void broadcastAbortRefund());
for (const id of [
  "action-fold", "action-check", "action-call", "action-aggressive", "action-timeout"
]) {
  elements[id].addEventListener("click", () => void authorizeGameEdge(elements[id]));
}
elements["copy-link"].addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(elements["share-link"].value);
    elements["copy-state"].textContent = "Copied. Send it through a private channel.";
  } catch (_) {
    elements["share-link"].select();
    elements["copy-state"].textContent = "Select and copy the link manually.";
  }
});
elements["copy-funding-address"].addEventListener("click", async () => {
  const address = elements["funding-address"].value;
  if (!address) return;
  try {
    await navigator.clipboard.writeText(address);
    elements["copy-funding-address"].textContent = "Copied";
    setTimeout(() => { elements["copy-funding-address"].textContent = "Copy"; }, 1_500);
  } catch (_) {
    elements["funding-address"].select();
  }
});
window.addEventListener("hashchange", () => { if (!session) showLobby(); });
window.addEventListener("pagehide", () => stopStagingDeposit(false));

const startupPending = loadStartupPending();
if (session) {
  showGame();
} else {
  showLobby();
  if (startupPending?.kind === "create") {
    selectTab("create");
    void createGame(startupPending);
  } else if (startupPending?.kind === "join") {
    selectTab("join");
    elements["join-hint"].textContent = "Resuming the saved guest-seat claim.";
    void joinGame(startupPending);
  } else if (location.hash.startsWith("#/join/")) {
    void joinGame();
  }
}
