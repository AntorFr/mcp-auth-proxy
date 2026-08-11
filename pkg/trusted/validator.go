// Package trusted validates bearer JWTs issued by an external, pre-trusted
// OIDC issuer (e.g. Authelia, Keycloak, Okta) against its published JWKS.
//
// This complements the built-in IdP: interactive clients keep going through
// the regular OAuth flow handled by this proxy, while non-interactive
// (machine-to-machine) callers may present an access token minted directly
// by the trusted issuer, provided its audience matches this proxy. Headless
// workloads therefore never need a browser-based login.
package trusted

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// validMethods lists the asymmetric signing algorithms accepted for trusted
// tokens. Symmetric algorithms (HS*) are deliberately excluded: accepting
// them would let anyone holding the public JWKS material forge tokens.
var validMethods = []string{"RS256", "PS256", "ES256"}

// minRefreshInterval bounds how often the JWKS endpoint is re-fetched when
// tokens reference an unknown key ID, so a flood of bad tokens cannot be
// turned into a request flood against the issuer.
const minRefreshInterval = time.Minute

const httpTimeout = 10 * time.Second

// Validator checks bearer JWTs against a trusted issuer's JWKS.
type Validator struct {
	issuer   string
	jwksURI  string // discovered from the issuer metadata when empty
	audience string
	client   *http.Client
	logger   *zap.Logger

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	lastRefresh time.Time
}

// NewValidator builds a validator for tokens issued by issuer with the given
// audience. jwksURI may be empty, in which case it is discovered lazily from
// the issuer's /.well-known/openid-configuration document (lazily so the
// proxy still starts while the issuer is momentarily unreachable).
func NewValidator(issuer, jwksURI, audience string, logger *zap.Logger) (*Validator, error) {
	if issuer == "" {
		return nil, fmt.Errorf("trusted token issuer must not be empty")
	}
	if audience == "" {
		return nil, fmt.Errorf("trusted token audience must not be empty")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Validator{
		issuer:   issuer,
		jwksURI:  jwksURI,
		audience: audience,
		client:   &http.Client{Timeout: httpTimeout},
		logger:   logger,
	}, nil
}

// clockLeeway absorbs clock skew between the issuer and this proxy. Tokens
// are often presented within the same second they are minted (a workload
// refreshes its token right before connecting); without leeway a validator
// clock trailing the issuer's rejects them on nbf/iat.
const clockLeeway = 60 * time.Second

// Validate parses and verifies a bearer token: signature against the JWKS,
// issuer, audience and expiry. It returns the token claims on success.
// Rejections are logged at warn level (reason only, never the token).
func (v *Validator) Validate(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		return v.key(ctx, kid)
	},
		jwt.WithValidMethods(validMethods),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockLeeway),
	)
	if err != nil {
		v.logger.Warn("trusted token rejected", zap.Error(err))
		return nil, err
	}
	if !token.Valid {
		v.logger.Warn("trusted token rejected", zap.String("reason", "token invalid"))
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// key returns the public key for kid, refreshing the JWKS cache when the kid
// is unknown (rate-limited by minRefreshInterval). An empty kid is accepted
// only when the key set contains exactly one signing key.
func (v *Validator) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if key, ok := v.lookup(kid); ok {
		return key, nil
	}
	if time.Since(v.lastRefresh) < minRefreshInterval {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	if key, ok := v.lookup(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *Validator) lookup(kid string) (crypto.PublicKey, bool) {
	if kid == "" {
		if len(v.keys) == 1 {
			for _, key := range v.keys {
				return key, true
			}
		}
		return nil, false
	}
	key, ok := v.keys[kid]
	return key, ok
}

// refresh fetches the JWKS (discovering its URI first if needed) and
// replaces the key cache. Callers must hold v.mu.
func (v *Validator) refresh(ctx context.Context) error {
	v.lastRefresh = time.Now()

	if v.jwksURI == "" {
		uri, err := v.discoverJWKSURI(ctx)
		if err != nil {
			return fmt.Errorf("failed to discover JWKS URI: %w", err)
		}
		v.jwksURI = uri
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURI, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: unexpected status %d", resp.StatusCode)
	}

	var keySet jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := map[string]crypto.PublicKey{}
	for _, key := range keySet.Keys {
		if !key.Valid() || !key.IsPublic() || key.Use == "enc" {
			continue
		}
		keys[key.KeyID] = key.Key
	}
	if len(keys) == 0 {
		return fmt.Errorf("JWKS at %s contains no usable signing keys", v.jwksURI)
	}
	v.keys = keys
	v.logger.Debug("refreshed trusted issuer JWKS",
		zap.String("jwks_uri", v.jwksURI), zap.Int("keys", len(keys)))
	return nil
}

// discoverJWKSURI reads jwks_uri from the issuer's OIDC discovery document.
func (v *Validator) discoverJWKSURI(ctx context.Context) (string, error) {
	discoveryURL := strings.TrimSuffix(v.issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, discoveryURL)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("no jwks_uri in discovery document at %s", discoveryURL)
	}
	return doc.JWKSURI, nil
}
