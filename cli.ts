import * as _hex from "https://deno.land/std@0.170.0/encoding/hex.ts";
import * as flags from "https://deno.land/std@0.170.0/flags/mod.ts";
import * as ed25519 from "https://esm.sh/@noble/ed25519@1.7.1";

let PrivateKey = toBytes(Deno.env.get("PRIVATE_KEY") || "");
let Endpoint = "";

async function start() {
  const args = flags.parse(Deno.args, {
    string: ["url", "key", "_"],
  });

  if (args.key) {
    PrivateKey = toBytes(args.key);
  }

  if (args.url) {
    Endpoint = args.url;
  }

  // Check params
  if (PrivateKey.length != 32) {
    throw new Error("Invalid private key length");
  }

  // if (/^https?\:\/\/.*/.test(Endpoint)) {
  //   console.log(Endpoint);
  //   throw new Error("Invalid URL");
  // }

  await sendCreate(args._[0] as string);
}

async function sendCreate(text: string) {
  const str = new TextEncoder().encode(
    JSON.stringify({ message: text, nonce: crypto.randomUUID() }),
  );
  const sign = await ed25519.sign(str, PrivateKey);
  const res = await fetch(Endpoint, {
    method: "POST",
    body: str,
    headers: {
      "content-type": "application/json",
      "x-api-signature": toHex(sign),
    },
  });
  console.log(res.status, await res.json());
}

function toHex(buf: Uint8Array | ArrayBuffer) {
  if (buf instanceof ArrayBuffer) {
    buf = new Uint8Array(buf);
  }

  return new TextDecoder().decode(_hex.encode(buf as Uint8Array));
}

function toBytes(hex: string) {
  return _hex.decode(new TextEncoder().encode(hex));
}

if (import.meta.main) {
  start();
}
