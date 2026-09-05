const mode = new URL(window.location.href).searchParams.get("mode");

if (mode === "funded") {
  document.getElementById("practice-stakes-row")?.classList.add("hidden");
  document.getElementById("practice-mode-copy")?.classList.add("hidden");
  document.getElementById("funded-network-row")?.classList.remove("hidden");
  document.getElementById("funded-payout-row")?.classList.remove("hidden");
  document.getElementById("funded-mode-copy")?.classList.remove("hidden");
  await import("/app.js?v=13");
} else {
  await import("/dlog52-game.js");
}
