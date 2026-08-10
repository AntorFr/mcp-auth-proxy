package trusted

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type issuerFixture struct {
	server *httptest.Server
	keys   map[string]*rsa.PrivateKey
}

// newIssuerFixture spins up a fake OIDC issuer serving a discovery document
// and a JWKS built from the given key IDs.
func newIssuerFixture(t *testing.T, kids ...string) *issuerFixture {
	t.Helper()
	f := &issuerFixture{keys: map[string]*rsa.PrivateKey{}}
	for _, kid := range kids {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		f.keys[kid] = key
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   f.server.URL,
			"jwks_uri": f.server.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		keySet := jose.JSONWebKeySet{}
		for kid, key := range f.keys {
			keySet.Keys = append(keySet.Keys, jose.JSONWebKey{
				Key: &key.PublicKey, KeyID: kid, Use: "sig", Algorithm: "RS256",
			})
		}
		_ = json.NewEncoder(w).Encode(keySet)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *issuerFixture) sign(t *testing.T, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(f.keys[kid])
	require.NoError(t, err)
	return signed
}

func baseClaims(issuer, audience string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "machine-client",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func TestValidator_AcceptsValidTokenViaDiscovery(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, "", "https://mcp.example.com", nil)
	require.NoError(t, err)

	claims, err := v.Validate(context.Background(), f.sign(t, "kid1", baseClaims(f.server.URL, "https://mcp.example.com")))
	require.NoError(t, err)
	require.Equal(t, "machine-client", claims["sub"])
}

func TestValidator_AcceptsValidTokenViaExplicitJWKSURI(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, f.server.URL+"/jwks.json", "https://mcp.example.com", nil)
	require.NoError(t, err)

	_, err = v.Validate(context.Background(), f.sign(t, "kid1", baseClaims(f.server.URL, "https://mcp.example.com")))
	require.NoError(t, err)
}

func TestValidator_AcceptsAudienceList(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, "", "https://mcp.example.com", nil)
	require.NoError(t, err)

	claims := baseClaims(f.server.URL, "")
	claims["aud"] = []string{"https://other.example.com", "https://mcp.example.com"}
	_, err = v.Validate(context.Background(), f.sign(t, "kid1", claims))
	require.NoError(t, err)
}

func TestValidator_RejectsBadClaims(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, "", "https://mcp.example.com", nil)
	require.NoError(t, err)

	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" }},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "https://other.example.com" }},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"missing expiry", func(c jwt.MapClaims) { delete(c, "exp") }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			claims := baseClaims(f.server.URL, "https://mcp.example.com")
			tt.mutate(claims)
			_, err := v.Validate(context.Background(), f.sign(t, "kid1", claims))
			require.Error(t, err)
		})
	}
}

// A token symmetrically signed with public JWKS material must never pass:
// HS* algorithms would let anyone forge tokens from public information.
func TestValidator_RejectsSymmetricAlgorithm(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, "", "https://mcp.example.com", nil)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims(f.server.URL, "https://mcp.example.com"))
	token.Header["kid"] = "kid1"
	forged, err := token.SignedString([]byte("shared-secret"))
	require.NoError(t, err)

	_, err = v.Validate(context.Background(), forged)
	require.Error(t, err)
}

func TestValidator_RejectsUnknownKeyID(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, "", "https://mcp.example.com", nil)
	require.NoError(t, err)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, baseClaims(f.server.URL, "https://mcp.example.com"))
	token.Header["kid"] = "rogue"
	signed, err := token.SignedString(other)
	require.NoError(t, err)

	_, err = v.Validate(context.Background(), signed)
	require.Error(t, err)
}

func TestValidator_PicksUpRotatedKeys(t *testing.T) {
	f := newIssuerFixture(t, "kid1")
	v, err := NewValidator(f.server.URL, "", "https://mcp.example.com", nil)
	require.NoError(t, err)

	_, err = v.Validate(context.Background(), f.sign(t, "kid1", baseClaims(f.server.URL, "https://mcp.example.com")))
	require.NoError(t, err)

	// Rotate: the issuer publishes a new key under a new kid.
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f.keys["kid2"] = newKey

	// Within the refresh throttle window the new kid is still rejected...
	_, err = v.Validate(context.Background(), f.sign(t, "kid2", baseClaims(f.server.URL, "https://mcp.example.com")))
	require.Error(t, err)

	// ...and accepted once the throttle window has elapsed.
	v.mu.Lock()
	v.lastRefresh = time.Now().Add(-2 * minRefreshInterval)
	v.mu.Unlock()
	_, err = v.Validate(context.Background(), f.sign(t, "kid2", baseClaims(f.server.URL, "https://mcp.example.com")))
	require.NoError(t, err)
}

func TestNewValidator_RequiresIssuerAndAudience(t *testing.T) {
	_, err := NewValidator("", "", "aud", nil)
	require.Error(t, err)
	_, err = NewValidator("https://issuer.example.com", "", "", nil)
	require.Error(t, err)
}
