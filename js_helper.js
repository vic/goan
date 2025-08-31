import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Provide PRNG for the bundled nacl library
globalThis.self = {
  crypto: {
    getRandomValues: (buf) => {
      require('crypto').randomFillSync(buf);
      return buf;
    }
  }
};

// Polyfill atob for base64.decode used by lib/base64.js
if (typeof globalThis.atob === 'undefined') {
  globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('latin1');
}

// Ensure WebCrypto subtle exists
if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.subtle === 'undefined') {
  globalThis.crypto = globalThis.crypto || {};
  try {
    globalThis.crypto.subtle = require('crypto').webcrypto.subtle;
  } catch (e) {
    // let it error later if not available
  }
}

const { an } = await import('./an.js');

const [,,cmd, ...rest] = process.argv;

async function main(){
  if(cmd === 'gen'){
    const k = await an.gen();
    console.log(k);
    return;
  }
  if(cmd === 'sign'){
    const h = rest[0];
    const k = rest[1];
    const s = await an.sign(h, k);
    console.log(s);
    return;
  }
  if(cmd === 'open'){
    const m = rest[0];
    const o = await an.open(m);
    console.log(o);
    return;
  }
  console.error('unknown cmd');
  process.exit(2);
}

main().catch((e)=>{ console.error(e); process.exit(1); });
