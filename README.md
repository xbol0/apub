# Apub

Single user ActivityPub minimal implementation written in Deno.

This project can be deployed on [Deno Deploy](https://deno.com/deploy)

## Usage

```shell
deno run --allow-env --allow-net apub.ts
```

## Environments

- `DB_URL` **REQUIRED** The [deta.sh](https://deta.sh/) Base project key
- `PUBLIC_KEY` **REQUIRED** Admin public key, ED25519 32 bytes with hex encoding
- `USERNAME` **REQUIRED** Your name on this instance
- `PORT` Listen port, defaults 8000
- `BASE_PREFIX` Prefix for Deta Base name
