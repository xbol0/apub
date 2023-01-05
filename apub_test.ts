import * as base64 from "https://deno.land/std@0.170.0/encoding/base64.ts";
import * as _hex from "https://deno.land/std@0.170.0/encoding/hex.ts";

Deno.test(async function testInbox() {
  const username = Deno.env.get("USERNAME");
  const k = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign"],
  );
  const pub = await crypto.subtle.exportKey("spki", k.publicKey);
  const publickey = "-----BEGIN RSA PUBLIC KEY-----\n" + base64.encode(pub) +
    "\n-----END RSA PUBLIC KEY-----";
  const data = {
    "@context": "https://www.w3.org/ns/activitystreams",
    "summary": "Sally followed John",
    "type": "Follow",
    "actor": {
      "type": "Person",
      "name": "Sally",
      publicKey: {
        id: "https://example.com/users/Sally#main-key",
        owner: "https://example.com/users/Sally",
        publicKeyPem: publickey,
      },
    },
    "object": "http://localhost:8000/@" + username,
  };
  const buf = new TextEncoder().encode(JSON.stringify(data));
  const date = new Date().toUTCString();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const strToSign = new TextEncoder().encode(
    `(request-target): post /inbox\nhost: localhost:8000\ndate: ${date}\ndigest: SHA-256=${digest}`,
  );
  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    k.privateKey,
    strToSign,
  );
  const res = await fetch("http://localhost:8000/inbox", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      digest: `SHA-256=${toHex(digest)}`,
      signature:
        `keyId="https://example.com/users/Sally#main-key",headers="(request-target) host date digest",signature="${signature}"`,
    },
    body: buf,
  });
  console.log(res.status, await res.text());
});
function toHex(buf: Uint8Array | ArrayBuffer) {
  return new TextDecoder().decode(_hex.encode(new Uint8Array(buf)));
}
