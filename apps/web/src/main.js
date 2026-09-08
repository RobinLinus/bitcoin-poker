(async () => {
// Ask for a name while configuration and wallet loading run in the background.
let hasNickname = false;
try { hasNickname = !!localStorage.getItem("poker-player-name")?.trim(); } catch {}
if (!hasNickname && !/^#\/(table|host|guest)\//.test(location.hash)) document.body.classList.add("nickname-onboarding");
document.body.classList.toggle("invite-entry", location.hash.startsWith("#/join/"));
if (!document.body.classList.contains("nickname-onboarding") && !/^#\/(table|host|guest)\//.test(location.hash)) {
  document.body.classList.add("wallet-onboarding", "wallet-checking");
  document.getElementById("wallet-panel").classList.remove("hidden");
  document.getElementById("wallet-panel").open = true;
}
// Show the saved-table state before configuration or application modules load.
const reconnecting = /^#\/table\/[a-f0-9]{64}\/(alice|bob)$/.test(location.hash);
if (reconnecting) {
  document.body.classList.add("onchain-table");
  document.getElementById("lobby").classList.add("hidden");
  document.getElementById("game").classList.remove("hidden");
  document.getElementById("invite-card").classList.add("hidden");
  document.getElementById("table-message").classList.add("hidden");
  document.getElementById("preparation-title").textContent = "Reconnecting…";
  document.getElementById("preparation-progress").removeAttribute("value");
  document.getElementById("preparation-progress").setAttribute("aria-label", "Reconnecting");
  document.getElementById("table-preparation").classList.remove("hidden");
}
try {
const response = await fetch("/api/v1/config");
if (!response.ok) throw new Error("Could not load application configuration");
const config = await response.json();
if (config.mode === "onchainTest") {
  const defense = new Worker(new URL("./onchain/defense-worker.js",import.meta.url), {type:"module"});
  defense.postMessage(config);
  await import("./onchain/table-controller.js");
}
else {
  document.querySelector("#stakes-row strong").textContent = "Practice chips";
  document.getElementById("mode-copy").textContent =
    "Demo only — no real money is used.";
  document.getElementById("chain-panel").classList.add("hidden");
  document.body.classList.remove("entry-pending", "wallet-onboarding", "wallet-checking");
  await import("./practice/table-controller.js");
}

} catch (error) {
  if (!reconnecting) {
    document.body.classList.remove("nickname-onboarding", "entry-pending");
    document.body.classList.add("wallet-onboarding");
    const panel = document.getElementById("wallet-panel");
    panel.classList.remove("hidden"); panel.open = true;
    document.querySelector(".wallet-onboarding-title").textContent = "Couldn’t load the app";
    document.getElementById("wallet-status").textContent = "";
    document.getElementById("wallet-progress").classList.add("hidden");
    document.querySelector(".wallet-funding-details").classList.add("hidden");
    const retry = document.getElementById("wallet-retry");
    retry.classList.remove("hidden"); retry.textContent = "Retry"; retry.disabled = false; retry.onclick = () => location.reload();
    return;
  }
  console.error(error);
  document.getElementById("preparation-title").textContent = "Couldn’t reconnect";
  document.getElementById("preparation-progress").classList.add("hidden");
  const retry = document.createElement("button");
  retry.type = "button";
  retry.classList.remove("hidden"); retry.textContent = "Retry";
  retry.addEventListener("click", () => location.reload());
  document.getElementById("table-preparation").append(retry);
}

})();
