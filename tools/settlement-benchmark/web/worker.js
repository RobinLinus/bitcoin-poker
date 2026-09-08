const phases = {1:"dealerSetup",2:"graphCompilation",3:"transactionInventory",4:"cosigning",5:"snapshotEncoding",6:"recoveryInventory",7:"recoveryVerification",8:"complete"};
self.onmessage = async ({data:{full}}) => {
  let instance, currentPhase, phaseStarted, started;
  const timingsMs = {};
  const counts = {};
  let peakWasmBytes = 0;
  try {
    const compileStarted = performance.now();
    const bytes = await (await fetch("/benchmark.wasm")).arrayBuffer();
    const sha256 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), x=>x.toString(16).padStart(2,"0")).join("");
    const module = await WebAssembly.compile(bytes);
    const metadata = { full, expectedNodes:full?56132:26, wasmBytes:bytes.byteLength, wasmSha256:sha256, userAgent:navigator.userAgent, hardwareConcurrency:navigator.hardwareConcurrency, stackBytes:33554432 };
    const imports = {benchmark:{now_ms:()=>performance.now(),progress:(phase,done,total,artifactBytes)=> {
      const now = performance.now();
      if(phase===3) {counts.nodes=artifactBytes;counts.requests=total;}
      if(phase===5) {counts.signatures=done;counts.revealPackages=total;counts.adaptorSignatures=total*52;counts.responseBytes=artifactBytes;}
      if(phase===8) counts.snapshotBytes=artifactBytes;
      peakWasmBytes = Math.max(peakWasmBytes,instance.exports.memory.buffer.byteLength);
      if (phase !== currentPhase) {
        if (currentPhase !== undefined) timingsMs[phases[currentPhase]] = now-phaseStarted;
        currentPhase=phase;phaseStarted=now;
      }
      postMessage({type:"progress",...metadata,phase:phases[phase],done,total,artifactBytes,timingsMs:{...timingsMs},elapsedMs:now-started,peakWasmBytes});
    }}};
    instance = await WebAssembly.instantiate(module, imports);
    timingsMs.loadAndCompile = performance.now()-compileStarted;
    started=performance.now();
    if (instance.exports.tree_run(full?1:0)!==1) {
      const error = new TextDecoder().decode(new Uint8Array(instance.exports.memory.buffer,instance.exports.tree_error_ptr(),instance.exports.tree_error_len()));
      throw new Error(error);
    }
    const inventoryDigest=Array.from(new Uint8Array(instance.exports.memory.buffer,instance.exports.tree_inventory_digest_ptr(),32),x=>x.toString(16).padStart(2,"0")).join("");
    postMessage({type:"result",ok:true,inventoryDigest,...metadata,...counts,timingsMs,elapsedMs:performance.now()-started,signingMs:instance.exports.tree_timing(0),receiverVerificationMs:instance.exports.tree_timing(1),peakWasmBytes});
  } catch(error) {
    postMessage({type:"result",ok:false,full,error:String(error.stack??error),timingsMs,elapsedMs:started===undefined?null:performance.now()-started,peakWasmBytes});
  }
};
