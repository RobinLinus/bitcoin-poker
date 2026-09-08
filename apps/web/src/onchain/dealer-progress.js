import {encode, decode} from './wasm-client.js';

// A relay page can cross an attempt boundary. Advance both copies of the
// authenticated dealer state before consuming the next attempt's first frame.
export async function advanceDealerRetry(setup, persist, owners=[0,1]) {
  const state=decode(setup(7));
  if(!state.retry) return false;
  for(const owner of owners) setup(6,encode(state.attempt+1),owner);
  await persist();
  return true;
}
