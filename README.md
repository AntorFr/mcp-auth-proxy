# MCP Auth Proxy

![Secure your MCP server with OAuth 2.1 — in a minute](./mcp-auth-proxy.svg)

> If you found value here, please consider starring.

## Overview

- **Drop-in OAuth 2.1/OIDC gateway for MCP servers — put it in front, no code changes.**
- **Your IdP, your choice**: Google, GitHub, or any OIDC provider — e.g. Okta, Auth0, Azure AD, Keycloak — plus optional password.
- **Flexible user matching**: Support exact matching and glob patterns for user authorization (e.g., `*@company.com`)
- **Publish local MCP servers safely**: Supports all stdio, SSE, and HTTP transports. For stdio, traffic is converted to `/mcp`. For SSE/HTTP, it's proxied as-is. Of course, with authentication.
- **Verified across major MCP clients**: Claude, Claude Code, ChatGPT, GitHub Copilot, Cursor, etc. — the proxy smooths client-specific quirks for consistent auth.

---

📖 **For detailed usage, configuration, and examples, see the [Documentation](https://sigbit.github.io/mcp-auth-proxy/)**

## Quickstart

> Domain binding & 80/443 must be accessible from outside.

Download binary from [release](https://github.com/sigbit/mcp-auth-proxy/releases) page.

If you use stdio transport

```sh
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password changeme \
  -- npx -y @modelcontextprotocol/server-filesystem ./
```

That's it! Your HTTP endpoint is now available at `https://{your-domain}/mcp`.

- stdio (when a command is specified): MCP endpoint is https://{your-domain}/mcp.
- SSE/HTTP (when a URL is specified): MCP endpoint uses the backend’s original path (no conversion).

> Already have certificates? Pass `--tls-cert-file` and `--tls-key-file` instead of `--tls-accept-tos`.

## Trusted external issuer (machine-to-machine)

Interactive clients authenticate through the proxy's built-in OAuth flow.
Headless workloads (agents, schedulers, CI) cannot complete a browser login;
for those you can declare a **trusted external OIDC issuer** whose bearer
JWTs are accepted directly, in addition to the proxy's own tokens:

```sh
./mcp-auth-proxy \
  --external-url https://mcp.example.com \
  --trusted-token-issuer https://auth.example.com \
  ...
```

A bearer token is then accepted when all of the following hold:

- it is signed by the issuer (validated against its JWKS, discovered via
  `/.well-known/openid-configuration` or overridden with
  `--trusted-token-jwks-uri`);
- its `iss` claim equals `--trusted-token-issuer` exactly;
- its `aud` claim contains `--trusted-token-audience` (default: the external
  URL without its trailing slash) — mint one token per protected service so a
  leaked token cannot be replayed elsewhere;
- it carries a valid, unexpired `exp` claim. Only asymmetric signatures
  (RS256/PS256/ES256) are accepted.

Claims of trusted tokens are flat (there is no `userinfo` wrapper), so if you
use `--header-mapping` with such tokens, set `--header-mapping-base /`.

| Flag | Env | Description |
|------|-----|-------------|
| `--trusted-token-issuer` | `TRUSTED_TOKEN_ISSUER` | Issuer URL. Empty (default) disables the feature |
| `--trusted-token-jwks-uri` | `TRUSTED_TOKEN_JWKS_URI` | JWKS override; discovered from issuer metadata when empty |
| `--trusted-token-audience` | `TRUSTED_TOKEN_AUDIENCE` | Required audience; defaults to the external URL without trailing slash |

## Why not MCP Gateway?

mcp-auth-proxy: **A lightweight proxy that adds authentication to any MCP server** (optional stdio→HTTP(S) conversion)  
MCP Gateway: **A hub to orchestrate multiple MCP servers** (aggregation, catalog integration)

### When to choose `mcp-auth-proxy`

- **You just need to add auth to one or a few MCPs** (enforce OAuth/OIDC/password-only)
- **Catalog integration and aggregation aren’t needed** (e.g., self-hosted or independently managed MCP deployments)

### When to choose MCP Gateway

- **You need to manage multiple MCPs centrally** (aggregation, policies/permissions, auditing, centralized logging)
- **You want catalog integration and aggregation**

_Note_: They are not mutually exclusive. You can **put `mcp-auth-proxy` in front of a Gateway's public endpoint to enforce authentication** if the Gateway itself doesn't handle it.

**TL;DR:** Orchestrate many → Gateway / Expose safely & quickly → mcp-auth-proxy

## Verified MCP Client

| MCP Client        | Status | Notes                                            |
| ----------------- | ------ | ------------------------------------------------ |
| Claude - Web      | ✅     |                                                  |
| Claude - Desktop  | ✅     |                                                  |
| Claude Code       | ✅     |                                                  |
| ChatGPT - Web     | ✅     | Need to implement `search` and `fetch` tools.(1) |
| ChatGPT - Desktop | ✅     | Need to implement `search` and `fetch` tools.(1) |
| GitHub Copilot    | ✅     |                                                  |
| Cursor            | ✅     |                                                  |

- \*1: https://platform.openai.com/docs/mcp
