import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const here = new URL("./", import.meta.url);
const [html, css, app, relay, tableStakes, tableView, esplora] = await Promise.all([
  readFile(new URL("index.html", here), "utf8"),
  readFile(new URL("styles.css", here), "utf8"),
  readFile(new URL("app.js", here), "utf8"),
  readFile(new URL("../src/lib.rs", here), "utf8"),
  readFile(new URL("../../../browser/flow/table-stakes.js", here), "utf8"),
  readFile(new URL("../../../browser/flow/table-view.js", here), "utf8"),
  readFile(new URL("../../../browser/chain-adapter/esplora.js", here), "utf8"),
]);

function fragment(start, end) {
  const startIndex = html.indexOf(start);
  const endIndex = html.indexOf(end, startIndex);
  assert.notEqual(startIndex, -1, `missing ${start}`);
  assert.notEqual(endIndex, -1, `missing ${end}`);
  return html.slice(startIndex, endIndex);
}

function appFragment(start, end) {
  const startIndex = app.indexOf(start);
  const endIndex = app.indexOf(end, startIndex);
  assert.notEqual(startIndex, -1, `missing app fragment ${start}`);
  assert.notEqual(endIndex, -1, `missing app fragment ${end}`);
  return app.slice(startIndex, endIndex);
}

const tableStatus = fragment('<div class="table-message">', '<section id="funding-card"');
assert.match(tableStatus, /id="table-phase"/u);
assert.match(tableStatus, /id="table-detail"/u);
assert.match(tableStatus, /id="broadcast-refund"[^>]*hidden/u);
assert.match(tableStatus, />\s*Return funds\s*</u);
assert.doesNotMatch(tableStatus, /package|signature|transaction|recovery|origin/iu);
assert.equal((html.match(/role="status"/gu) ?? []).length, 1);
assert.match(css, /\.table-message\s*\{[\s\S]*?left:\s*50%;[\s\S]*?transform:\s*translate\(-50%,\s*-50%\);/u);
assert.match(css, /\.table-funding-card\s*\{[\s\S]*?left:\s*50%;[\s\S]*?transform:\s*translate\(-50%,\s*-50%\);/u);
assert.match(html, /id="action-bar" class="action-bar hidden"/u);
assert.match(html, /id="local-stack" class="seat-stack">Stack · —</u);
assert.match(html, /id="opponent-stack" class="seat-stack">Stack · —</u);
assert.match(html, /id="table-small-blind"/u);
assert.match(html, /id="table-big-blind"/u);
assert.match(app, /formatBitcoinAmount\(balances\.localStackSat\)/u);
assert.match(app, /formatBitcoinAmount\(balances\.opponentStackSat\)/u);
assert.match(app, /formatBitcoinAmount\(balances\.potSat\)/u);
assert.match(relay, /\.route\(\s*"\/browser\/ui\/bitcoin-amount\.js",\s*get\(bitcoin_amount_script\),?\s*\)/u);
assert.match(relay, /include_str!\("\.\.\/\.\.\/\.\.\/browser\/ui\/bitcoin-amount\.js"\)/u);
assert.doesNotMatch(
  [html, app, tableStakes, tableView, esplora].join("\n"),
  /\bsats?(?:oshi(?:s)?)?\b/iu,
  "normal browser display sources must not contain legacy Bitcoin unit labels",
);

const funding = fragment('<section id="funding-card"', '<div class="seat seat-local">');
assert.match(funding, /id="funding-amount"/u);
assert.match(funding, /id="funding-address"/u);
assert.match(funding, /Your deposit/u);
assert.match(funding, /Opponent deposit/u);
assert.match(funding, /The game starts automatically after both deposits confirm\./u);
assert.doesNotMatch(funding, /package|signature|transaction|recovery|origin/iu);

const removedPlayerUiIds = [
  "recovery-code-input", "recover-seat", "recovery-code-output", "copy-recovery-code",
  "ready-card", "ready-button", "origin-card", "protect-refund", "lock-funds",
  "broadcast-origin", "refund-recovery", "refund-raw-tx", "copy-refund-tx",
  "download-refund-tx", "deal-card", "activation-card", "authorize-activation",
  "broadcast-game-tx", "action-special", "test-message", "send-message", "message-list",
  "leave-game", "short-game-id", "relay-status",
];
for (const id of removedPlayerUiIds) {
  assert.doesNotMatch(html, new RegExp(`id="${id}"`, "u"), `${id} must not exist in the DOM`);
  assert.doesNotMatch(
    app,
    new RegExp(`elements\\["${id}"\\]`, "u"),
    `${id} must not retain a render or listener branch`,
  );
}
assert.doesNotMatch(html, /developer-only|Relay test console|Advanced setup|Saved seat/iu);
assert.doesNotMatch(css, /developer-only|seat-recovery|refund-recovery|setup-list|message-list/iu);
assert.match(css, /\.side-panel:not\(:has\(> :not\(\.hidden\)\)\)\s*\{\s*display:\s*none;/u);

const htmlIds = [...html.matchAll(/\bid="([^"]+)"/gu)].map((match) => match[1]);
assert.equal(new Set(htmlIds).size, htmlIds.length, "HTML ids must be unique");
const knownHtmlIds = new Set(htmlIds);
const elementRegistry = appFragment("const elements = Object.fromEntries(", "const deploymentLabel");
const registeredIds = [...elementRegistry.matchAll(/"([a-z][a-z0-9-]+)"/gu)]
  .map((match) => match[1]);
for (const id of registeredIds) {
  assert.ok(knownHtmlIds.has(id), `app element registry references missing DOM id ${id}`);
}
for (const match of app.matchAll(/elements\["([^"]+)"\]/gu)) {
  assert.ok(knownHtmlIds.has(match[1]), `app render references missing DOM id ${match[1]}`);
}
for (const match of app.matchAll(/\belements\.([a-z][a-z0-9-]*)/gu)) {
  assert.ok(knownHtmlIds.has(match[1]), `app render references missing DOM id ${match[1]}`);
}

const playerText = html
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/giu, " ")
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/giu, " ")
  .replace(/<[^>]+>/gu, " ")
  .replace(/\s+/gu, " ");
assert.doesNotMatch(
  playerText,
  /\b(?:debug|protocol|package|signature|recovery|transaction|origin|wasm)\b/iu,
  "player-facing copy must not expose implementation jargon",
);
assert.match(app, /let resumeRoute = parseResumeRoute\(location\.hash\);/u);
assert.match(app, /let session = loadSession\(\);/u);
assert.doesNotMatch(app, /RESUME_STORE\.removeSession/u);
assert.match(app, /case AutomaticSetupAction\.SEND_READY:[\s\S]+await sendReady\(\);/u);
assert.doesNotMatch(app, /sendReady\)\.addEventListener|protectOriginRefund\)\.addEventListener/u);

const setupAuthorization = appFragment(
  "function authorizeAutomaticSetup()",
  "async function protectOriginRefund()",
);
assert.match(setupAuthorization, /const packageId = agreedOriginPackageId\(agreed\);/u);
assert.doesNotMatch(setupAuthorization, /agreed\.frame\.packageId/u);
assert.match(app, /phase === GamePhase\.ACTIVE/u);
assert.match(app, /phase === GamePhase\.HALTED/u);
assert.doesNotMatch(app, /phase === (?:9|11)/u);
assert.match(
  setupAuthorization,
  /!signatures\.localRefund \|\| !signatures\.peerRefund \|\| !state\.signedRefundTxHex/u,
);
assert.match(
  setupAuthorization,
  /state\.setupAuthorizationPackageId = packageId;[\s\S]+saveOriginCoordinatorState\(activeSession\);[\s\S]+readBackOriginCoordinatorState\(activeSession\);/u,
);
const fundingRelease = appFragment(
  "async function releaseOriginFundingSignature()",
  "async function submitOriginFundingTransaction(",
);
assert.match(fundingRelease, /originRefundVerified[\s\S]+originSetupAuthorized\(activeSession\)/u);

process.stdout.write("player UI contains only automatic poker flow controls and one central status\n");
