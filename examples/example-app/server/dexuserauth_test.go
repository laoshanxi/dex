package server

// Tests for the dexuser administration authentication: the /session exchange,
// the cookie/bearer gate, and the token checks behind them.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// dexuserFixture is an issuer (a JWKS endpoint), a signing key, and a Server
// wired for dexuser authentication against it.
type dexuserFixture struct {
	t     *testing.T
	srv   *Server
	gate  http.Handler
	key   *rsa.PrivateKey
	kid   string
	iss   string
	token func(claims map[string]any) string
}

func newDexuserFixture(t *testing.T, audience string) *dexuserFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key"

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Use: "sig", Algorithm: "RS256"}},
		})
	}))
	t.Cleanup(jwks.Close)

	t.Setenv(envDexuserIssuer, jwks.URL)
	t.Setenv(envDexuserAudience, audience)

	srv := &Server{dexuser: newDexuserAuth(&http.Client{Timeout: 5 * time.Second})}
	if srv.dexuser == nil {
		t.Fatal("dexuser auth not configured")
	}
	f := &dexuserFixture{
		t:   t,
		srv: srv,
		gate: srv.dexuserGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin"))
		})),
		key: key,
		kid: kid,
		iss: jwks.URL,
	}
	f.token = func(claims map[string]any) string {
		return f.sign(key, kid, claims)
	}
	return f
}

// sign serializes claims and signs them RS256 with the given key.
func (f *dexuserFixture) sign(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	f.t.Helper()
	return signJWT(f.t, key, kid, claims)
}

// validToken returns a token that passes every check, with overrides on top.
func (f *dexuserFixture) validToken(overrides map[string]any) string {
	f.t.Helper()

	claims := map[string]any{
		"iss": f.iss,
		"sub": "user-1",
		"aud": defaultDexuserAudience,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return f.token(claims)
}

func (f *dexuserFixture) session(bearer string) *httptest.ResponseRecorder {
	f.t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	f.srv.handleDexuserSession(rr, req)
	return rr
}

func (f *dexuserFixture) get(path string, hdr map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.gate.ServeHTTP(rr, req)
	return rr
}

// TestDexuserSessionExchange: POST /session with a valid bearer answers 204
// and sets the session cookie; the cookie then admits requests through the
// gate; neither endpoint is open without it.
func TestDexuserSessionExchange(t *testing.T) {
	f := newDexuserFixture(t, "")

	// No bearer: refused.
	rr := f.session("")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer: got %d, want 401", rr.Code)
	}

	// Valid bearer: 204 with the cookie.
	rr = f.session(f.validToken(nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("valid bearer: got %d, want 204", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != dexuserSessionCookie {
		t.Fatalf("expected one %s cookie, got %v", dexuserSessionCookie, cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure {
		t.Fatalf("cookie attributes wrong: %+v", c)
	}
	if len(c.Value) < 22 { // 128 bits, base64url
		t.Fatalf("session id too short: %q", c.Value)
	}

	// The cookie admits a request through the gate, and is renewed on use.
	rr = f.get("/admin", map[string]string{"Cookie": c.String()})
	if rr.Code != http.StatusOK || rr.Body.String() != "admin" {
		t.Fatalf("cookie through gate: got %d %q", rr.Code, rr.Body.String())
	}
	if len(rr.Result().Cookies()) != 1 {
		t.Fatalf("sliding renewal must re-issue the cookie")
	}

	// No cookie, no bearer: 401 page.
	rr = f.get("/admin", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: got %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "dexuser") {
		t.Fatalf("401 page missing: %q", rr.Body.String())
	}

	// A valid bearer admits a request directly, no cookie needed.
	rr = f.get("/admin", map[string]string{"Authorization": "Bearer " + f.validToken(nil)})
	if rr.Code != http.StatusOK {
		t.Fatalf("bearer through gate: got %d, want 200", rr.Code)
	}
}

// TestDexuserSessionCookieSecureOverTLS: a request arriving over TLS — an
// HTTPS upstream, e.g. a TLS-terminating sidecar — gets a Secure cookie; the
// plain-loopback deployment above keeps none.
func TestDexuserSessionCookieSecureOverTLS(t *testing.T) {
	f := newDexuserFixture(t, "")
	ts := httptest.NewTLSServer(f.srv.routes())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.validToken(nil))
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("session over TLS: got %d, want 204", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != dexuserSessionCookie {
		t.Fatalf("expected one %s cookie, got %v", dexuserSessionCookie, cookies)
	}
	if !cookies[0].Secure {
		t.Fatalf("cookie issued over TLS must carry Secure: %+v", cookies[0])
	}
}

// TestDexuserSessionCookieSecureViaProxyHeader: the main deployment is a
// TLS-terminating proxy in front of a plain upstream, which forces
// X-Forwarded-Proto on every request — that must yield Secure too, while a
// forged or absent header over plain HTTP must not.
func TestDexuserSessionCookieSecureViaProxyHeader(t *testing.T) {
	f := newDexuserFixture(t, "")
	ts := httptest.NewServer(f.srv.routes())
	defer ts.Close()

	exchange := func(xfp string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/session", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.validToken(nil))
		if xfp != "" {
			req.Header.Set("X-Forwarded-Proto", xfp)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("session with XFP %q: got %d, want 204", xfp, resp.StatusCode)
		}
		cookies := resp.Cookies()
		if len(cookies) != 1 || cookies[0].Name != dexuserSessionCookie {
			t.Fatalf("expected one %s cookie, got %v", dexuserSessionCookie, cookies)
		}
		return resp
	}

	if !exchange("https").Cookies()[0].Secure {
		t.Fatal("trusted proxy reporting https must yield a Secure cookie")
	}
	if exchange("http").Cookies()[0].Secure {
		t.Fatal("plain-HTTP request (forged or absent XFP) must not yield a Secure cookie")
	}
}

// TestDexuserLogout: DELETE /session deletes the server-side session and
// expires the cookie, after which the old cookie no longer opens admin routes.
func TestDexuserLogout(t *testing.T) {
	f := newDexuserFixture(t, "")

	rr := f.session(f.validToken(nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("session: got %d, want 204", rr.Code)
	}
	c := rr.Result().Cookies()[0]

	// The fresh cookie opens an admin route.
	if rr := f.get("/admin", map[string]string{"Cookie": c.String()}); rr.Code != http.StatusOK {
		t.Fatalf("cookie through gate: got %d", rr.Code)
	}

	// Logout with the cookie: 204 and the deletion cookie (Max-Age=0).
	req := httptest.NewRequest(http.MethodDelete, "/session", nil)
	req.Header.Set("Cookie", c.String())
	rr = httptest.NewRecorder()
	f.srv.handleDexuserLogout(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204", rr.Code)
	}
	expired := rr.Result().Cookies()
	if len(expired) != 1 || expired[0].Name != dexuserSessionCookie || expired[0].MaxAge != -1 {
		t.Fatalf("logout must send the deletion cookie, got %v", expired)
	}

	// The logged-out cookie no longer opens anything.
	if rr := f.get("/admin", map[string]string{"Cookie": c.String()}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session admitted: got %d, want 401", rr.Code)
	}

	// No credentials at all: refused, like every gated route.
	req = httptest.NewRequest(http.MethodDelete, "/session", nil)
	rr = httptest.NewRecorder()
	f.srv.handleDexuserLogout(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logout: got %d, want 401", rr.Code)
	}

	// A valid bearer logs out too — 204, with no session to delete.
	req = httptest.NewRequest(http.MethodDelete, "/session", nil)
	req.Header.Set("Authorization", "Bearer "+f.validToken(nil))
	rr = httptest.NewRecorder()
	f.srv.handleDexuserLogout(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("bearer logout: got %d, want 204", rr.Code)
	}
}

// TestDexuserTokenChecks: the checks a bearer must pass. Every failure is the
// same 401.
func TestDexuserTokenChecks(t *testing.T) {
	f := newDexuserFixture(t, "")

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	bad := map[string]map[string]any{
		"expired":        {"exp": time.Now().Add(-time.Minute).Unix()},
		"no exp":         {"exp": nil},
		"wrong issuer":   {"iss": "https://elsewhere.example.com"},
		"no issuer":      {"iss": nil},
		"wrong audience": {"aud": "someone-else"},
		"no audience":    {"aud": nil},
	}
	for name, overrides := range bad {
		if rr := f.session(f.validToken(overrides)); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401 (body %q)", name, rr.Code, rr.Body.String())
		}
	}

	// A signature by a key the issuer never published.
	if rr := f.session(f.sign(otherKey, "other-key", map[string]any{
		"iss": f.iss, "sub": "u", "aud": defaultDexuserAudience,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})); rr.Code != http.StatusUnauthorized {
		t.Errorf("unknown key: got %d, want 401", rr.Code)
	}

	// Not a JWT at all.
	if rr := f.session("garbage"); rr.Code != http.StatusUnauthorized {
		t.Errorf("garbage: got %d, want 401", rr.Code)
	}

	// The audience may be a list that contains the configured one, with or
	// without company.
	for _, aud := range []any{defaultDexuserAudience, []string{"first", defaultDexuserAudience}} {
		if rr := f.session(f.validToken(map[string]any{"aud": aud})); rr.Code != http.StatusNoContent {
			t.Errorf("aud %v: got %d, want 204", aud, rr.Code)
		}
	}

	// A configured audience other than the default is honored: a token whose
	// aud contains it passes, one carrying only the default does not.
	f2 := newDexuserFixture(t, "appmesh-api-2")
	if rr := f2.session(f2.validToken(map[string]any{"aud": "appmesh-api-2"})); rr.Code != http.StatusNoContent {
		t.Errorf("custom audience, matching aud: got %d, want 204", rr.Code)
	}
	if rr := f2.session(f2.validToken(map[string]any{"aud": defaultDexuserAudience})); rr.Code != http.StatusUnauthorized {
		t.Errorf("custom audience, default aud token: got %d, want 401", rr.Code)
	}
}

// TestDexuserSessionExpiry: a session dies with its TTL and slides while
// used.
func TestDexuserSessionExpiry(t *testing.T) {
	f := newDexuserFixture(t, "")
	t.Setenv(envDexuserTTL, "60ms")
	f.srv.dexuser = newDexuserAuth(&http.Client{Timeout: 5 * time.Second})
	if f.srv.dexuser == nil {
		t.Fatal("dexuser auth not configured")
	}

	rr := f.session(f.validToken(nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("session: got %d", rr.Code)
	}
	c := rr.Result().Cookies()[0]

	rr = f.get("/admin", map[string]string{"Cookie": c.String()})
	if rr.Code != http.StatusOK {
		t.Fatalf("fresh session refused: %d", rr.Code)
	}

	time.Sleep(80 * time.Millisecond)
	rr = f.get("/admin", map[string]string{"Cookie": c.String()})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expired session admitted: %d", rr.Code)
	}
}

// TestDexuserFailsClosedWithoutIssuer: no APP_MESH_DEXUSER_ISSUER, no
// administration surface — every route behind the gate answers 401.
func TestDexuserFailsClosedWithoutIssuer(t *testing.T) {
	t.Setenv(envDexuserIssuer, "")
	t.Setenv(envDexuserAudience, "")

	srv := &Server{dexuser: newDexuserAuth(&http.Client{})}
	if srv.dexuser != nil {
		t.Fatal("unset issuer must disable dexuser auth")
	}

	gate := srv.dexuserGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the gate must not admit anything unconfigured")
	}))
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("gate: got %d, want 401", rr.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	rr = httptest.NewRecorder()
	srv.handleDexuserSession(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/session: got %d, want 401", rr.Code)
	}
}

// TestDexuserTTLParsing pins the accepted spellings of the TTL.
func TestDexuserTTLParsing(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"":      defaultDexuserTTL,
		"30m":   30 * time.Minute,
		"1h30m": 90 * time.Minute,
		"1800":  30 * time.Minute,
		"10s":   10 * time.Second,
	} {
		got, err := parseDexuserTTL(v)
		if err != nil || got != want {
			t.Errorf("parseDexuserTTL(%q) = %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"-5m", "0", "soon", "0s"} {
		if got, err := parseDexuserTTL(v); err == nil {
			t.Errorf("parseDexuserTTL(%q) = %v, want an error", v, got)
		}
	}
}

// TestDexuserJWKSRefreshOnUnknownKid: a key the cached set lacks triggers a
// refetch, which is what keeps issuer key rotation working.
func TestDexuserJWKSRefreshOnUnknownKid(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rotated := false
	fetches := 0
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		key, kid := key1, "k1"
		if rotated {
			key, kid = key2, "k2"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Use: "sig", Algorithm: "RS256"}},
		})
	}))
	defer issuer.Close()

	t.Setenv(envDexuserIssuer, issuer.URL)
	t.Setenv(envDexuserAudience, "")

	// Shorten the refetch rate limit and let the window elapse, so the rotated
	// token's refetch is not swallowed by it.
	oldWait := jwksRetryWait
	jwksRetryWait = 20 * time.Millisecond
	t.Cleanup(func() { jwksRetryWait = oldWait })

	auth := newDexuserAuth(&http.Client{Timeout: 5 * time.Second})
	if auth == nil {
		t.Fatal("dexuser auth not configured")
	}

	claims := map[string]any{
		"iss": issuer.URL,
		"sub": "user-1",
		"aud": defaultDexuserAudience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// The first verification fetches the JWKS.
	if err := auth.verify(context.Background(), signJWT(t, key1, "k1", claims)); err != nil {
		t.Fatalf("first key rejected: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("expected one JWKS fetch, got %d", fetches)
	}

	// The issuer rotates. A token under the new kid must trigger a refetch
	// and then verify.
	rotated = true
	time.Sleep(40 * time.Millisecond)
	if err := auth.verify(context.Background(), signJWT(t, key2, "k2", claims)); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	if fetches < 2 {
		t.Fatalf("unknown kid must trigger a JWKS refetch, fetches = %d", fetches)
	}
}

// signJWT is the fixture's signer, standalone for tests without the fixture.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
