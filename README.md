# Apub

Single user ActivityPub minimal implementation written in Deno.

This project can be deployed on [Deno Deploy](https://deno.com/deploy)

## Usage

```shell
deno run --allow-env --allow-net apub.ts
```

## Environments

- `DB_URL` The [deta.sh](https://deta.sh/) Base project key
- `PORT` Listen port, defaults 8000
- `PUBLIC_KEY` Admin public key, ED25519 32 bytes with hex encoding
- `BASE_PREFIX` Prefix for Deta Base name
- `USERNAME` Your name on this instance
