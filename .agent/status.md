# Status — mcp-auth-proxy (fork AntorFr)

> MàJ : 2026-08-11

**État :** Fork de `sigbit/mcp-auth-proxy` (base v2.10.2) portant le mode
**trusted external issuer** : les sidecars MCP acceptent, en plus de leur OAuth
interactif, les Bearer JWT frappés par Authelia (JWKS, `iss` exact, `aud` par
service, RS256/PS256/ES256 seulement). Flags `--trusted-token-issuer` /
`--trusted-token-jwks-uri` / `--trusted-token-audience`. Suite de tests verte
(amont + nouveaux), release-please et docs désactivés sur le fork.
v2.10.2-antor.2 : leeway d'horloge 60 s (un jeton présenté dans la seconde
de sa frappe était rejeté sur nbf/iat par dérive d'horloge inter-nodes) +
log warn des rejets trusted.

**Prochaines étapes :**
- [ ] Proposer le patch en PR amont (feature générique) — si mergée, le fork disparaît
- [ ] Rebase sur l'amont quand il bouge (patch étroit : pkg/trusted + 1 fonction du proxy)
