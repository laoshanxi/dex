package server

// Tests for the RFC 7009 revocation endpoint (POST /auth/revoke).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

// doRevoke posts a token to /auth/revoke with the given client credentials.
func doRevoke(t *testing.T, s *Server, token, user, pass string) *httptest.ResponseRecorder {
	t.Helper()

	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/auth", "revoke")

	v := url.Values{}
	v.Add("token", token)

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

// doPasswordGrantFull is doPasswordGrant but returns the whole token set, for
// tests that need the access token too.
func doPasswordGrantFull(t *testing.T, s *Server) tokenResponse {
	t.Helper()

	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/token")

	v := url.Values{}
	v.Add("scope", "openid profile email offline_access")
	v.Add("grant_type", "password")
	v.Add("username", "user@example.com")
	v.Add("password", "secret")

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test", "barfoo")

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "password grant failed: %s", rr.Body.String())

	var resp tokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.RefreshToken, "no refresh token in password grant response")
	require.NotEmpty(t, resp.AccessToken, "no access token in password grant response")
	return resp
}

// TestTokenRevocationRevokesRefreshTokenFamily: revoking any member of a
// refresh-token family — here the value a rotation has already retired — kills
// the whole family, current token included.
func TestTokenRevocationRevokesRefreshTokenFamily(t *testing.T) {
	httpServer, s := newTestServer(t, func(c *Config) {
		c.PasswordConnector = "local"
	})
	defer httpServer.Close()
	seedLocalPasswordDB(t, s)

	first := doPasswordGrant(t, s)

	// Rotate once, so the family has a retired and a current value.
	rr := doRefreshGrant(t, s, first, 0)
	require.Equal(t, http.StatusOK, rr.Code, "rotation failed: %s", rr.Body.String())
	var rotated tokenResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rotated))
	require.NotEqual(t, first, rotated.RefreshToken, "refresh token was not rotated")

	// Revoking the retired value is revoking the family.
	rr = doRevoke(t, s, first, "test", "barfoo")
	require.Equal(t, http.StatusOK, rr.Code, "revocation failed: %s", rr.Body.String())
	require.Empty(t, rr.Body.String(), "RFC 7009 §2.2: the response body is empty")

	// The current value is dead too, not just the retired one.
	rr = doRefreshGrant(t, s, rotated.RefreshToken, 0)
	require.Equal(t, http.StatusBadRequest, rr.Code, "current token must be revoked with the family: %s", rr.Body.String())
	require.Contains(t, rr.Body.String(), "invalid_grant")

	// And the row is gone from storage.
	var tok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(first, &tok))
	_, err := s.storage.GetRefresh(t.Context(), tok.RefreshId)
	require.ErrorIs(t, err, storage.ErrNotFound)
}

// TestTokenRevocationUnknownTokenAnswers200: RFC 7009 §2.2 — an unknown,
// malformed, or already-revoked token is answered with 200, so the response
// reveals nothing about what the server does or does not hold.
func TestTokenRevocationUnknownTokenAnswers200(t *testing.T) {
	httpServer, s := newTestServer(t, func(c *Config) {
		c.PasswordConnector = "local"
	})
	defer httpServer.Close()
	seedLocalPasswordDB(t, s)

	for _, token := range []string{
		"not-a-token",
		"garbage.zzz.bbb",                       // JWT-shaped but unverifiable
		"cGViYmxlOnNlY3JldA",                    // decodable, no such refresh token
		"cGViYmxlOnNlY3JldA.more.segments.here", // wrong shape outright
	} {
		rr := doRevoke(t, s, token, "test", "barfoo")
		require.Equal(t, http.StatusOK, rr.Code, "token %q", token)
	}

	// Revoking the same token twice is the same as revoking an unknown one.
	first := doPasswordGrant(t, s)
	require.Equal(t, http.StatusOK, doRevoke(t, s, first, "test", "barfoo").Code)
	require.Equal(t, http.StatusOK, doRevoke(t, s, first, "test", "barfoo").Code)
}

// TestTokenRevocationClientAuthentication: the endpoint authenticates clients
// the way the token endpoint does. Missing or wrong credentials are 401; a
// public client (no secret) identifies with client_id alone, as it does at the
// token endpoint.
func TestTokenRevocationClientAuthentication(t *testing.T) {
	httpServer, s := newTestServer(t, func(c *Config) {
		c.PasswordConnector = "local"
	})
	defer httpServer.Close()
	seedLocalPasswordDB(t, s)
	require.NoError(t, s.storage.CreateClient(t.Context(), storage.Client{
		ID:           "public",
		RedirectURIs: []string{"foo://bar.com/"},
	}))

	rr := doRevoke(t, s, "any-token", "", "")
	require.Equal(t, http.StatusUnauthorized, rr.Code, "no credentials must be refused")
	require.Equal(t, `Basic realm="dex"`, rr.Header().Get("WWW-Authenticate"))

	rr = doRevoke(t, s, "any-token", "test", "wrong")
	require.Equal(t, http.StatusUnauthorized, rr.Code, "wrong secret must be refused")

	rr = doRevoke(t, s, "any-token", "public", "")
	require.Equal(t, http.StatusOK, rr.Code, "public clients identify with client_id alone")

	// A malformed request still fails loudly: no token at all is 400.
	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/auth", "revoke")
	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test", "barfoo")
	rrec := httptest.NewRecorder()
	s.ServeHTTP(rrec, req)
	require.Equal(t, http.StatusBadRequest, rrec.Code)
}

// TestTokenRevocationOnlyIssuedClient: a token held by another client is not
// revoked by a different authenticated client; the response is the same 200,
// so the endpoint does not become an oracle for other clients' tokens.
func TestTokenRevocationOnlyIssuedClient(t *testing.T) {
	httpServer, s := newTestServer(t, func(c *Config) {
		c.PasswordConnector = "local"
	})
	defer httpServer.Close()
	seedLocalPasswordDB(t, s)
	require.NoError(t, s.storage.CreateClient(t.Context(), storage.Client{
		ID:           "other",
		Secret:       "othersecret",
		RedirectURIs: []string{"foo://bar.com/"},
	}))

	first := doPasswordGrant(t, s)

	rr := doRevoke(t, s, first, "other", "othersecret")
	require.Equal(t, http.StatusOK, rr.Code)

	// The token survives: it was never the caller's to revoke.
	rr = doRefreshGrant(t, s, first, 0)
	require.Equal(t, http.StatusOK, rr.Code, "another client's revocation must not take effect: %s", rr.Body.String())
}

// TestTokenRevocationAccessTokenSemantics documents what revoking an access
// token means for dex's stateless JWTs: the presented token itself keeps
// verifying until it expires — there is no row behind it to delete — but the
// refresh-token family its subject resolves to is revoked, so no further
// tokens can be minted for that authorization.
func TestTokenRevocationAccessTokenSemantics(t *testing.T) {
	httpServer, s := newTestServer(t, func(c *Config) {
		c.PasswordConnector = "local"
	})
	defer httpServer.Close()
	seedLocalPasswordDB(t, s)

	tokens := doPasswordGrantFull(t, s)

	rr := doRevoke(t, s, tokens.AccessToken, "test", "barfoo")
	require.Equal(t, http.StatusOK, rr.Code, "access token revocation failed: %s", rr.Body.String())

	// The family behind it is dead: the refresh token no longer redeems.
	rr = doRefreshGrant(t, s, tokens.RefreshToken, 0)
	require.Equal(t, http.StatusBadRequest, rr.Code, "access token revocation must kill the refresh family: %s", rr.Body.String())
	require.Contains(t, rr.Body.String(), "invalid_grant")

	// The presented access token itself is stateless and unexpired: it still
	// introspects as active. That is the documented best-effort semantics, not
	// a leak — the token dies at exp on its own.
	data := url.Values{}
	data.Set("token", tokens.AccessToken)
	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/token", "introspect")
	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test", "barfoo")
	irec := httptest.NewRecorder()
	s.ServeHTTP(irec, req)
	require.Equal(t, http.StatusOK, irec.Code)
	var intro map[string]any
	require.NoError(t, json.Unmarshal(irec.Body.Bytes(), &intro))
	require.Equal(t, true, intro["active"], "the stateless JWT stays active until exp; the family behind it is what was revoked")
}
