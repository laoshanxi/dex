package server

// dexuserauth.go authenticates the dexuser administration surface. As App
// Mesh's Dex admin console this app is reached through the UI's reverse proxy
// and has power over every Dex account, so the pages and endpoints under
// /admin require a session: POST /session exchanges the App Mesh engine's
// bearer token (an RS256 JWT from the configured issuer) for a session
// cookie, DELETE /session revokes it, and every administration route accepts
// that cookie or a bearer token directly — the cookie for a browser, the
// bearer for the engine's scripts.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// The environment contract with the App Mesh launcher.
const (
	envDexuserIssuer   = "APP_MESH_DEXUSER_ISSUER"
	envDexuserAudience = "APP_MESH_DEXUSER_AUDIENCE"
	envDexuserTTL      = "APP_MESH_DEXUSER_SESSION_TTL"

	defaultDexuserAudience = "appmesh-api"
	defaultDexuserTTL      = 30 * time.Minute

	// dexuserSessionCookie is the administration session cookie from POST
	// /session. SameSite=Strict because the console is used from the UI's own
	// pages; Secure is set when the request arrived over TLS.
	dexuserSessionCookie = "dexuser_session"

	// jwksCacheTTL is how long a fetched JWKS is trusted without a refresh.
	jwksCacheTTL = time.Hour

	// jwksFetchTimeout bounds a JWKS fetch end to end. The fetch runs under the
	// key-set lock and the caller's client has no total deadline in production
	// (http.DefaultClient, or dial/TLS timeouts only), so a hung issuer would
	// otherwise stall every admin verification.
	jwksFetchTimeout = 5 * time.Second
)

// jwksRetryWait is how often an unknown key id may trigger a refetch, so a
// client naming random kids cannot turn the endpoint into a fetch loop. A
// variable for the tests to shorten; an abrupt issuer rotation costs at most
// this much refusal, and dex's own rotation publishes the new key alongside
// the old one first, so in practice the cache already holds it.
var jwksRetryWait = time.Minute

// dexuserAuth holds the administration authentication: the OIDC verifier for
// bearer tokens and the in-memory session store. One instance serves the whole
// process, which is all a single-node dexuser needs.
type dexuserAuth struct {
	issuer   string
	audience string
	ttl      time.Duration
	verifier *oidc.IDTokenVerifier
	sessions *dexuserSessions
}

// newDexuserAuth reads the dexuser contract from the environment. It returns
// nil when APP_MESH_DEXUSER_ISSUER is unset: without an issuer to verify
// against there is no authentication, and the callers fail closed rather than
// serve an open administration console. The issuer is used verbatim (modulo a
// trailing slash) both to build the JWKS URL, {issuer}/keys, and as the value
// the token's iss claim must carry.
func newDexuserAuth(client *http.Client) *dexuserAuth {
	issuer := strings.TrimSuffix(strings.TrimSpace(os.Getenv(envDexuserIssuer)), "/")
	if issuer == "" {
		return nil
	}

	audience := os.Getenv(envDexuserAudience)
	if audience == "" {
		audience = defaultDexuserAudience
	}

	ttl, err := parseDexuserTTL(os.Getenv(envDexuserTTL))
	if err != nil {
		log.Printf("dexuser: %s (%q), using the default %s", err, os.Getenv(envDexuserTTL), defaultDexuserTTL)
		ttl = defaultDexuserTTL
	}

	// A dedicated client for the JWKS fetch: the total timeout above over the
	// caller's transport, which is what keeps custom root CAs working against
	// a private issuer (Timeout and Transport coexist).
	keySet := &jwksKeySet{
		url:    issuer + "/keys",
		client: &http.Client{Timeout: jwksFetchTimeout, Transport: client.Transport},
	}
	auth := &dexuserAuth{
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
		verifier: oidc.NewVerifier(issuer, keySet, &oidc.Config{
			// The audience check is the "aud contains the configured audience"
			// rule; the OIDC verifier applies it to a string or an array aud
			// alike, and requires a present, unexpired token with a matching
			// issuer on top of the RS256 signature check.
			ClientID:             audience,
			SupportedSigningAlgs: []string{"RS256"},
		}),
		sessions: newDexuserSessions(ttl),
	}
	return auth
}

// parseDexuserTTL accepts a Go duration ("30m") or a plain number of seconds
// ("1800"), so the launcher need not care which spelling it uses.
func parseDexuserTTL(v string) (time.Duration, error) {
	if v == "" {
		return defaultDexuserTTL, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("dexuser: %s must be positive", envDexuserTTL)
		}
		return d, nil
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second, nil
	}
	return 0, fmt.Errorf("dexuser: %s is neither a duration nor a number of seconds", envDexuserTTL)
}

// verify checks a bearer token: an RS256 signature over the issuer's JWKS, the
// exact issuer, a present and unexpired exp, and an aud containing the
// configured audience.
func (a *dexuserAuth) verify(ctx context.Context, bearer string) error {
	_, err := a.verifier.Verify(ctx, bearer)
	return err
}

// handleDexuserSession serves POST /session: a Bearer token in, a session
// cookie out. 204 with the cookie on success, 401 on anything else.
func (s *Server) handleDexuserSession(w http.ResponseWriter, r *http.Request) {
	if s.dexuser == nil {
		dexuserUnauthorized(w, "dexuser authentication is not configured ("+envDexuserIssuer+" is unset)")
		return
	}
	bearer := bearerToken(r)
	if bearer == "" {
		dexuserUnauthorized(w, "missing bearer token")
		return
	}
	if err := s.dexuser.verify(r.Context(), bearer); err != nil {
		log.Printf("dexuser: session token rejected: %v", err)
		dexuserUnauthorized(w, "invalid bearer token")
		return
	}
	id := s.dexuser.sessions.mint()
	s.dexuser.setSessionCookie(w, r, id, http.StatusNoContent)
}

// handleDexuserLogout serves DELETE /session: with the gate's authentication,
// it deletes the server-side session and expires the cookie, ending a stolen
// or shared browser session now rather than at the TTL. A bearer caller has
// no session to delete and gets 204; a stale cookie is simply 401 again.
func (s *Server) handleDexuserLogout(w http.ResponseWriter, r *http.Request) {
	id, ok := s.dexuserAdmit(w, r)
	if !ok {
		return
	}
	if id != "" {
		s.dexuser.sessions.revoke(id)
	}
	s.dexuser.expireSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// dexuserAdmit runs the gate's authentication — a valid session cookie or a
// valid bearer token — writing the same brief 401 page when it refuses. It
// returns the session id, empty for a bearer caller, which carries no session.
func (s *Server) dexuserAdmit(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.dexuser == nil {
		dexuserUnauthorized(w, "dexuser authentication is not configured ("+envDexuserIssuer+" is unset)")
		return "", false
	}

	if bearer := bearerToken(r); bearer != "" {
		if err := s.dexuser.verify(r.Context(), bearer); err != nil {
			log.Printf("dexuser: bearer token rejected: %v", err)
			dexuserUnauthorized(w, "invalid bearer token")
			return "", false
		}
		return "", true
	}

	if c, err := r.Cookie(dexuserSessionCookie); err == nil && s.dexuser.sessions.valid(c.Value) {
		return c.Value, true
	}

	dexuserUnauthorized(w, "authentication required")
	return "", false
}

// dexuserGate admits a request to the administration surface with either a
// valid session cookie or a valid bearer token. Anything else gets the same
// brief 401 page, whichever check failed.
func (s *Server) dexuserGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.dexuserAdmit(w, r)
		if !ok {
			return
		}
		if id != "" {
			// Sliding renewal, on both sides: the store's expiry was just
			// moved by valid, and the cookie's MaxAge follows so the browser
			// keeps the cookie as long as the session is genuinely alive.
			s.dexuser.setSessionCookie(w, r, id, 0)
		}
		next.ServeHTTP(w, r)
	})
}

// setSessionCookie writes the session cookie. status, when non-zero, is
// written with it.
func (a *dexuserAuth) setSessionCookie(w http.ResponseWriter, r *http.Request, id string, status int) {
	http.SetCookie(w, &http.Cookie{
		Name:     dexuserSessionCookie,
		Value:    id,
		Path:     "/", // valid for the UI embed (browser path /dexuser/… on the UI origin) and standalone use alike; not tied to the prefix the proxy strips upstream
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// HTTPS browser origin: a direct TLS request, or the trusted proxy's
		// forced X-Forwarded-Proto when it terminates TLS in front of a plain
		// upstream. A forged header over plain HTTP only makes the browser drop
		// the Secure cookie (fail-closed).
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge: int(a.ttl / time.Second),
	})
	if status != 0 {
		w.WriteHeader(status)
	}
}

// expireSessionCookie sends the deletion cookie (Max-Age=0) for the session
// cookie, clearing the browser's copy at logout.
func (a *dexuserAuth) expireSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     dexuserSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// bearerToken extracts the Authorization: Bearer value. The scheme is matched
// case-insensitively, as RFC 7235 requires.
func bearerToken(r *http.Request) string {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// dexuserUnauthorized writes the brief 401 page every refused dexuser request
// answers with. The page is the same for every refusal: which check failed is
// in the server log, not in the response.
func dexuserUnauthorized(w http.ResponseWriter, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body><p>dexuser: authentication required.</p><p>%s</p></body></html>\n", detail)
}

// dexuserSessions is the in-memory session store: random ids mapped to
// expiries. Single instance, single node; a restart logs every browser out,
// which for an administration console is the safe default.
type dexuserSessions struct {
	mu       sync.Mutex
	ttl      time.Duration
	sessions map[string]time.Time
}

func newDexuserSessions(ttl time.Duration) *dexuserSessions {
	return &dexuserSessions{
		ttl:      ttl,
		sessions: make(map[string]time.Time),
	}
}

// mint creates a session with a fresh 128-bit id from crypto/rand.
func (st *dexuserSessions) mint() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("dexuser: out of randomness: " + err.Error())
	}
	id := base64.RawURLEncoding.EncodeToString(b)

	st.mu.Lock()
	st.sweepLocked()
	st.sessions[id] = time.Now().Add(st.ttl)
	st.mu.Unlock()
	return id
}

// valid reports whether id is a live session and, when it is, slides its
// expiry — the session lasts as long as it is used, no longer.
func (st *dexuserSessions) valid(id string) bool {
	if id == "" {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()
	if _, ok := st.sessions[id]; !ok {
		return false
	}
	st.sessions[id] = time.Now().Add(st.ttl)
	return true
}

// sweepLocked drops expired sessions. Called on the way in, often enough for a
// console with a handful of operators. Callers hold the lock.
func (st *dexuserSessions) sweepLocked() {
	now := time.Now()
	for id, exp := range st.sessions {
		if now.After(exp) {
			delete(st.sessions, id)
		}
	}
}

// revoke deletes a session immediately; logout must not wait out the TTL.
func (st *dexuserSessions) revoke(id string) {
	st.mu.Lock()
	delete(st.sessions, id)
	st.mu.Unlock()
}

// jwksKeySet serves the issuer's signing keys from {issuer}/keys, cached and
// periodically refreshed. It implements oidc.KeySet for the verifier above.
type jwksKeySet struct {
	url    string
	client *http.Client

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time // last successful fetch
	attemptAt time.Time // last fetch attempt, successful or not
}

// VerifySignature verifies an RS256 signature with a cached key and returns
// the token payload.
func (ks *jwksKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	// RS256 only: ParseSigned rejects every other algorithm, so a token
	// signed HS256 with the public key as the secret never reaches a
	// verification attempt.
	tok, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	if len(tok.Signatures) != 1 {
		return nil, errors.New("dexuser: token must carry exactly one signature")
	}
	key, err := ks.key(ctx, tok.Signatures[0].Protected.KeyID)
	if err != nil {
		return nil, err
	}
	return tok.Verify(key)
}

// key returns the signing key for kid, fetching the JWKS on first use,
// hourly after that, and — what keeps key rotation working — when a token
// names a key the cached set lacks, at most once per jwksRetryWait.
func (ks *jwksKeySet) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.keys == nil || time.Since(ks.fetchedAt) > jwksCacheTTL {
		ks.fetchLocked(ctx)
	}
	if key, ok := ks.keys[kid]; ok {
		return key, nil
	}
	if time.Since(ks.attemptAt) > jwksRetryWait {
		ks.fetchLocked(ctx)
	}
	if key, ok := ks.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("dexuser: no signing key %q at %s", kid, ks.url)
}

// fetchLocked replaces the cached keys. A failed fetch keeps the previous
// set — a key the issuer just rotated out of publication may still verify
// tokens it signed moments ago. Callers hold the lock, which makes each fetch
// single-flight.
func (ks *jwksKeySet) fetchLocked(ctx context.Context) {
	ks.attemptAt = time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.url, nil)
	if err != nil {
		log.Printf("dexuser: JWKS request for %s: %v", ks.url, err)
		return
	}
	resp, err := ks.client.Do(req)
	if err != nil {
		log.Printf("dexuser: fetching JWKS from %s: %v", ks.url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("dexuser: JWKS %s answered %s", ks.url, resp.Status)
		return
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		log.Printf("dexuser: parsing JWKS from %s: %v", ks.url, err)
		return
	}

	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if _, ok := k.Key.(*rsa.PublicKey); !ok {
			continue // signature keys here are RSA; anything else is not ours to use
		}
		keys[k.KeyID] = k.Key
	}
	if len(keys) == 0 {
		log.Printf("dexuser: JWKS %s carries no usable signature keys; keeping the previous set", ks.url)
		return
	}
	ks.keys = keys
	ks.fetchedAt = time.Now()
}
