import { bytesToHex } from "./room-session.js";
const fill = (value) => new Uint8Array(32).fill(value);
export const demoIdentities = [
  { secret: fill(3), xonly: Uint8Array.from([83,31,230,6,129,52,80,61,39,35,19,50,39,200,103,172,143,166,200,60,83,126,154,68,195,197,189,189,203,31,227,55]) },
  { secret: fill(5), xonly: Uint8Array.from([98,192,160,70,218,204,232,109,221,3,67,198,211,199,199,156,34,8,186,13,156,156,242,74,109,4,109,33,210,31,144,247]) },
].sort((a, b) => bytesToHex(a.xonly).localeCompare(bytesToHex(b.xonly)));
