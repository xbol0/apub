import * as http from "https://deno.land/std@0.170.0/http/server.ts";
import * as _hex from "https://deno.land/std@0.170.0/encoding/hex.ts";
import * as base64 from "https://deno.land/std@0.170.0/encoding/base64.ts";
import * as ed25519 from "https://esm.sh/@noble/ed25519@1.7.1";

class ErrorResponse extends Error {
  status: number;

  constructor(message: string, status = 400) {
    super(message);

    this.status = status;
  }

  toResponse() {
    return new Response(
      JSON.stringify({ error: this.message }),
      { status: this.status, headers: CommonHeader },
    );
  }
}

class Database {
  secret: string;
  endpoint: string;

  constructor(secret: string) {
    if (!secret) throw new Error("Invalid DB secret");
    this.secret = secret;
    const [id] = secret.split("_");
    this.endpoint = `https://database.deta.sh/v1/${id}/`;
  }

  async _request<T>(
    method: string,
    base: string,
    target: string,
    body: unknown = null,
  ) {
    const uri = new URL(`${base}/${target}`, this.endpoint);
    const res = await fetch(uri.href, {
      method,
      body: body === null ? body : JSON.stringify(body),
      headers: { "content-type": "application/json", "x-api-key": this.secret },
    });

    // Throw the first error when request fail
    if (res.status >= 400) {
      const err = await res.json() as { errors: string[] };
      throw new ErrorResponse(err.errors[0]);
    }

    return await res.json() as T;
  }

  async fetch<T extends AnyObject>(
    base: string,
    id: string,
  ): Promise<T | null> {
    try {
      return await this._request<T>("GET", base, `items/${id}`);
    } catch {
      return null;
    }
  }

  query<T>(
    base: string,
    query: unknown[] = [],
    opts?: Partial<{ limit: number; last: string }>,
  ): Promise<{ items: T[]; paging: { size: number; last: string } }> {
    return this._request("POST", base, "query", { ...opts, query });
  }

  async queryAll<T>(base: string, query: unknown[] = []): Promise<T[]> {
    let result: T[] = [], last = "";
    while (true) {
      const tmp = await this.query<T>(base, query, { last });
      result = result.concat(tmp.items);

      if ("last" in tmp.paging) {
        last = tmp.paging.last;
        continue;
      }

      return result;
    }
  }

  async insert(base: string, item: AnyObject, expires?: number) {
    if (expires) item.__expires = expires;
    type Res = { key: string };
    const result = await this._request<Res>("POST", base, "items", { item });
    return result.key;
  }

  async put(base: string, items: AnyObject[], expires?: number) {
    if (expires) items = items.map((i) => ({ ...i, __expires: expires }));
    await this._request("PUT", base, "items", { items });
  }

  async update(base: string, key: string, params: DBUpdateParams) {
    await this._request("PATCH", base, `items/${key}`, params);
  }

  async delete(base: string, key: string) {
    await this._request("DELETE", base, `items/${key}`);
  }
}

const port = parseInt(Deno.env.get("PORT") || "8000");
const db = new Database(Deno.env.get("DB_URL")!);
const Username = Deno.env.get("USERNAME") || "me";
const AdminPublicKey = toBytes(Deno.env.get("PUBLIC_KEY")!);
const Origin = Deno.env.get("HOSTNAME") || "";
let PrivateKey: CryptoKey;
let PublicKey: string;

const Prefix = Deno.env.get("BASE_PREFIX") || "apub_";
const BaseSummary = Prefix + "summary";
const BaseFollowers = Prefix + "followers";
const BaseFollowing = Prefix + "following";
const BaseNonce = Prefix + "nonce";
const BaseOutbox = Prefix + "outbox";

const CommonHeader = {
  "content-type": "application/json",
  "server": "apub",
  "access-control-allow-origin": "*",
};

const Router = new Map<string, http.Handler>();
Router.set("GET/.well-known/webfinger", handleWebfinger);
Router.set("GET/@" + Username, handleAccount);
Router.set(
  "GET/followers",
  collectionHandler<FollowerItem>("followers", BaseFollowers, (i) => i.href),
);
Router.set(
  "GET/following",
  collectionHandler<FollowerItem>("following", BaseFollowing, (i) => i.href),
);
Router.set(
  "GET/outbox",
  collectionHandler("outbox", BaseOutbox, (i) => i),
);
Router.set("POST/account", handleUpdateAccount);
Router.set("POST/create", handleCreate);
Router.set("POST/inbox", handleInbox);

async function start() {
  // Checking params for initialize
  //
  if (AdminPublicKey.length !== 32) {
    throw new Error("Invalid admin public key");
  }

  if (!/^[a-z][a-z0-9_]*$/.test(Username)) {
    throw new Error("Please specific a valid username");
  }

  // Initialize and start server
  //
  await init();
  http.serve(handler, { port });
}

async function init() {
  const mainPrivateKey = await db.fetch<{ value: string }>(
    BaseSummary,
    "main_private_key",
  );
  if (!mainPrivateKey) {
    // init new RSA keypair
    const k = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign"],
    );
    const [privateKeyBuf, publicKeyBuf] = await Promise.all([
      crypto.subtle.exportKey("pkcs8", k.privateKey),
      crypto.subtle.exportKey("spki", k.publicKey),
    ]);
    const privateKey = "-----BEGIN PRIVATE KEY-----\n" +
      base64.encode(privateKeyBuf) + "\n-----END PRIVATE KEY-----";
    const publicKey = "-----BEGIN PUBLIC KEY-----\n" +
      base64.encode(publicKeyBuf) + "\n-----END PUBLIC KEY-----";

    await db.put(BaseSummary, [
      { key: "main_private_key", value: privateKey },
      { key: "main_public_key", value: publicKey },
    ]);

    PrivateKey = k.privateKey;
    PublicKey = publicKey;

    console.log("Initialize keypair successful");
  } else {
    // Cache private key and public key
    const mainPublicKey = await db.fetch<{ value: string }>(
      BaseSummary,
      "main_public_key",
    );
    if (!mainPublicKey) throw new Error("Initialize may not successful");

    PublicKey = mainPublicKey.value;
    PrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      decodeKey(mainPrivateKey.value),
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["sign"],
    );
  }
}

async function handler(req: Request, info: http.ConnInfo) {
  if (req.method === "OPTIONS") return respond(null, 204);
  console.log(new Date(), req.method, req.url);

  const entry = req.method + new URL(req.url).pathname;
  const fn = Router.get(entry);

  if (!fn) return respond(null, 404);

  try {
    return await fn(req, info);
  } catch (err) {
    console.error(err);
    return respond(err);
  }
}

function handleWebfinger(req: Request) {
  const uri = new URL(req.url);
  const resource = uri.searchParams.get("resource");

  if (!resource || !resource.startsWith("acct:")) {
    throw new ErrorResponse(
      "Please make sure 'resource' parameter with 'acct:name@host' format in your request",
    );
  }

  const name = resource.slice(5, resource.indexOf("@", 5));

  if (name !== Username) {
    throw new ErrorResponse(`Not found record of '${resource}'`, 404);
  }

  return respond({
    subject: resource,
    aliases: [`${Origin || uri.origin}/@${Username}`],
    links: [{
      rel: "self",
      type: "application/activity+json",
      href: `${Origin || uri.origin}/@${name}`,
    }],
  });
}

function handleAccount(req: Request) {
  const uri = new URL(req.url);
  return respond({
    "@context": [
      "https://www.w3.org/ns/activitystreams",
      "https://w3id.org/security/v1",
    ],

    id: `${Origin || uri.origin}/@${Username}`,
    type: "Person",
    preferredUsername: Username,
    inbox: `${Origin || uri.origin}/inbox`,
    outbox: `${Origin || uri.origin}/outbox`,
    followers: `${Origin || uri.origin}/followers`,

    publicKey: {
      id: `${Origin || uri.origin}/@${Username}#main-key`,
      owner: `${Origin || uri.origin}/@${Username}`,
      publicKeyPem: PublicKey,
    },
  });
}

async function handleUpdateAccount(req: Request) {
  const input = await authenticate<UpdateAccountInput>(req);
  const params: { key: string; value: unknown }[] = [];

  if (typeof input.nickname === "string") {
    params.push({ key: "nickname", value: input.nickname });
  }

  if (typeof input.avatar === "string") {
    params.push({ key: "avatar", value: input.avatar });
  }

  await db.put(BaseSummary, params);
  return respond(null, 204);
}

function handleInbox(req: Request) {
  // validate signature
  if (!req.headers.has("digest") || !req.headers.has("signature")) {
    throw new ErrorResponse("Require 'Digest' and 'Signature' headers");
  }
  return respond(null, 202);
}

async function handleCreate(req: Request) {
  const json = await authenticate<CreateInput>(req);
  const uri = new URL(req.url);

  if (typeof json.message !== "string") {
    throw new ErrorResponse("Invalid message format", 400);
  }

  const id = newId();
  const data = {
    "@context": "https://www.w3.org/ns/activitystreams",

    key: id,
    id: `${Origin || uri.origin}/activity/${id}`,
    actor: `${Origin || uri.origin}/@${Username}`,
    type: "Create",
    to: ["https://www.w3.org/ns/activitystreams#Public"],
    cc: [`${Origin || uri.origin}/followers`],
    object: {
      id: `${Origin || uri.origin}/status/${id}`,
      type: "Note",
      published: new Date().toISOString(),
      attributedTo: `${Origin || uri.origin}/@${Username}`,
      to: ["https://www.w3.org/ns/activitystreams#Public"],
      content: json.message,
    },
  };
  await db.insert(BaseOutbox, data);

  queueMicrotask(() => queueSendtask(data));
  return respond(null, 201);
}

async function authenticate<T>(req: Request) {
  const sign = req.headers.get("x-api-signature");
  const nonce = req.headers.get("x-api-nonce");

  if (!sign) throw new ErrorResponse(`Required signature header`, 400);
  if (!nonce) throw new ErrorResponse(`Required nonce header`, 400);

  const text = await req.text();
  const body = new TextEncoder().encode(text + nonce);
  const signBuf = toBytes(sign);
  if (!await ed25519.verify(signBuf, body, AdminPublicKey)) {
    throw new ErrorResponse("Unverified signature", 403);
  }
  try {
    await db.insert(BaseNonce, { key: nonce }, ~~(Date.now() / 1000 + 30));
  } catch {
    throw new ErrorResponse("Nonce has been used", 400);
  }

  return JSON.parse(text) as T;
}

function respond(data: unknown, status = 200) {
  if (data instanceof ErrorResponse) return data.toResponse();
  return new Response(JSON.stringify(data), { status, headers: CommonHeader });
}

function collectionHandler<T>(
  path: string,
  base: string,
  mapFn: (i: T) => unknown,
) {
  return async (req: Request) => {
    const uri = new URL(req.url);

    if (uri.searchParams.has("key")) {
      const key = uri.searchParams.get("key")!;
      const res = await db.query<T>(base, [], { last: key });
      return respond({
        "@context": ["https://www.w3.org/ns/activitystreams"],
        type: "OrderedCollectionPage",
        totalItems: res.paging.size,
        id: `${Origin || uri.origin}/${path}?key=`,
        orderedItems: res.items.map(mapFn),
        next: res.items.length && res.paging.last
          ? `${Origin || uri.origin}/${path}?key=${res.paging.last}`
          : void 0,
      });
    } else {
      const res = await db.query(base);
      return respond({
        "@context": ["https://www.w3.org/ns/activitystreams"],
        type: "OrderedCollection",
        totalItems: res.paging.size,
        id: `${Origin || uri.origin}/${path}`,
        first: `${Origin || uri.origin}/${path}?key=`,
      });
    }
  };
}

function toHex(buf: Uint8Array | ArrayBuffer) {
  return new TextDecoder().decode(_hex.encode(new Uint8Array(buf)));
}

function toBytes(hex: string) {
  return _hex.decode(new TextEncoder().encode(hex));
}

function newId() {
  const ts = (0xffffffff - ~~(Date.now() / 1000)).toString(16);
  const rnd = toHex(crypto.getRandomValues(new Uint8Array(6)));
  return ts + rnd;
}

function decodeKey(str: string) {
  return base64.decode(str.split("\n").slice(1, -1).join(""));
}

async function queueSendtask(data: CreateAPData) {
  const list = await db.queryAll<Follower>(BaseFollowers);

  for (const item of list) await signAndSend(data, item.inbox);
}

async function signAndSend(data: unknown, inbox: string) {
  const encoder = new TextEncoder();
  const buf = encoder.encode(JSON.stringify(data));
  const uri = new URL(inbox);
  const date = new Date().toUTCString();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  const strToSign =
    `(request-target): post ${uri.pathname}\nhost: ${uri.host}\ndate: ${date}\ndigest: SHA-256=${hash}`;
  const strBuf = encoder.encode(strToSign);
  const sign = base64.encode(
    await crypto.subtle.sign({ name: "RSA-PSS" }, PrivateKey, strBuf),
  );

  const res = await fetch(inbox, {
    method: "POST",
    body: buf,
    headers: {
      "content-type": "application/ld+json",
      digest: `SHA-256=${toHex(hash)}`,
      signature: sign,
      host: uri.host,
      date: date,
    },
  });
  console.log(res.status, inbox);
  await res.body?.cancel();
}

if (import.meta.main) {
  if (AdminPublicKey.length != 32) throw new Error("Invalid Public Key");

  start();
}

type DBUpdateParams = Partial<{
  set: AnyObject;
  increment: Record<string, number>;
  append: Record<string, unknown[]>;
  prepend: Record<string, unknown[]>;
  delete: string[];
}>;

type FollowerItem = {
  key: string;
  href: string;
};

type UpdateAccountInput = {
  nickname: string;
  avatar: string;
};

type CreateInput = {
  message: string;
};

type CreateAPData = {
  to: string[];
  cc: string[];
};

type Follower = {
  key: string;
  actor: string;
  inbox: string;
};

type AnyObject = Record<string, unknown>;
