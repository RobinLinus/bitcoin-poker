import { BrowserDefense } from './browser-defense.js';
import { PreparationCheckpointStore } from '../storage/preparation-checkpoint-store.js';
let started=false;
self.onmessage=({data:config})=>{
  if(started) return;
  started=true;
  const monitors=['alice','bob'].map(sender=>new BrowserDefense(config,new PreparationCheckpointStore(`poker-channel-player-${sender}`)));
  const tick=async()=>{
    try {
      await navigator.locks.request('poker-browser-defense',{ifAvailable:true},async lock=>{
        if(lock) for(const monitor of monitors) await monitor.tick();
      });
    } catch(error) {console.warn('Browser recovery:',error);}
    setTimeout(tick,2000);
  };
  void tick();
};
