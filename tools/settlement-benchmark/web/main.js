let worker, latest, lastSaved = 0, remaining = 0;
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const fullButton = document.querySelector("#full");
const smokeButton = document.querySelector("#smoke");
const qualifyButton = document.querySelector("#qualify");
const parallelButton = document.querySelector("#parallel");
const parallelSmoke = document.querySelector("#parallel-smoke");
const parallelQualify = document.querySelector("#parallel-qualify");
let parallelMode = false;
const buttons = [fullButton, smokeButton, qualifyButton, parallelButton, parallelSmoke, parallelQualify];
const stop = document.querySelector("#stop");
const save = (data) => fetch("/results", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({...data, recordedAt: new Date().toISOString()}),
}).catch(error => { status.textContent += ` (report save failed: ${error})`; });
function finish() {
  worker?.terminate(); worker = null;
  buttons.forEach(button => button.disabled = false); stop.disabled = true;
}
function run(full) {
  buttons.forEach(button => button.disabled = true); stop.disabled = false;
  status.textContent = "Loading benchmark Wasm…";
  worker = new Worker(parallelMode ? "/parallel-worker.js" : "/worker.js", {type: "module"});
  worker.onmessage = async ({data}) => {
    if (remaining) data.trial = 4 - remaining;
    if (data.type === "result" && data.ok) {
      data.constructionTargetMet = data.timingsMs.transactionInventory <= 30_000;
    }
    latest = data; result.textContent = JSON.stringify(data, null, 2);
    status.textContent = data.type === "result"
      ? (data.ok ? "PASS — complete preparation and recovery verified" : "FAIL")
      : `${data.phase}: ${data.done.toLocaleString()} / ${data.total.toLocaleString()} · ${(data.elapsedMs / 1000).toFixed(1)} seconds`;
    if (data.type === "result" || performance.now() - lastSaved > 2000) {
      await save(data); lastSaved = performance.now();
    }
    if (data.type === "result") {
      finish();
      if (remaining > 1 && data.ok && (parallelMode ? data.setupTargetMet : data.constructionTargetMet)) { remaining -= 1; run(true); }
      else remaining = 0;
    }
  };
  worker.onerror = event => {
    status.textContent = `FAIL: ${event.message}`;
    void save({ok: false, error: event.message, latest}); remaining = 0; finish();
  };
  worker.postMessage({full});
}
fullButton.onclick = () => { parallelMode = false; run(true); };
smokeButton.onclick = () => { parallelMode = false; run(false); };
qualifyButton.onclick = () => { parallelMode = false; remaining = 3; run(true); };
stop.onclick = () => {
  remaining = 0; void save({ok: false, cancelled: true, latest}); finish();
  status.textContent = "Stopped; partial measurements saved.";
};

parallelButton.onclick = () => { parallelMode = true; run(true); };
parallelSmoke.onclick = () => { parallelMode = true; run(false); };
parallelQualify.onclick = () => { parallelMode = true; remaining = 3; run(true); };
