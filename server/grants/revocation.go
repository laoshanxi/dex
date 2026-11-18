package grants

// revocation.go serves RFC 7009 token revocation at POST /auth/revoke, next to
// the token endpoint, whose client authentication and helpers it shares.

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

// handleRevoke serves POST /auth/revoke (RFC 7009). A token the server does
// not know — unknown, expired, already revoked, or issued to another client —
// is answered with 200 all the same, so the response carries no information
// beyond that the token is now unusable. The only failures a caller can see
// are a malformed request (400) and bad client credentials (401).
func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		h.writeError(ctx, w, &oauth2.Error{Type: oauth2.InvalidRequest, Description: "method not allowed", Status: http.StatusBadRequest})
		return
	}
	if err := r.ParseForm(); err != nil {
		h.Logger.ErrorContext(ctx, "could not parse request body", "err", err)
		h.writeError(ctx, w, &oauth2.Error{Type: oauth2.InvalidRequest, Status: http.StatusBadRequest})
		return
	}

	// Client authentication, exactly as the token endpoint does it. Public
	// clients identify with client_id alone, which the shared AuthenticateClient
	// accepts — the same treatment the token endpoint gives them.
	id, secret, oerr := ClientCredentials(r, r.PostForm)
	if oerr != nil {
		h.writeError(ctx, w, oerr)
		return
	}
	client, oerr := AuthenticateClient(ctx, h.Storage, h.Logger, id, secret)
	if oerr != nil {
		if oerr.Status != http.StatusInternalServerError {
			w.Header().Set("WWW-Authenticate", `Basic realm="dex"`)
		}
		h.writeError(ctx, w, oerr)
		return
	}

	token := r.PostFormValue("token")
	if token == "" {
		h.writeError(ctx, w, &oauth2.Error{Type: oauth2.InvalidRequest, Description: "The POST body doesn't contain 'token' parameter.", Status: http.StatusBadRequest})
		return
	}
	// token_type_hint is optional and only an optimization for the server; a
	// dex token's type is decided by its shape below whatever the hint says.
	hint := r.PostFormValue("token_type_hint")
	_ = hint

	// RFC 7009 §2.2: the response body is empty.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if isJWT(token) {
		h.revokeAccessToken(ctx, client, token)
	} else {
		h.revokeRefreshToken(ctx, client, token)
	}

	w.WriteHeader(http.StatusOK)
}

// isJWT reports whether token is shaped like a JWT (three dot-separated
// segments). Refresh tokens are not, so this is the type decision for
// revocation, the same one introspection makes.
func isJWT(token string) bool {
	dots := 0
	for _, c := range token {
		if c == '.' {
			dots++
		}
	}
	return dots == 2
}

// revokeRefreshToken revokes the family the presented refresh token belongs
// to: the storage row that carries every value the family rotated through,
// plus its offline-session reference. A presented value that matches neither
// the current nor the retired token is not a member of the family and revokes
// nothing — answered, like every unknown token, with 200.
func (h *Handler) revokeRefreshToken(ctx context.Context, client storage.Client, token string) {
	rToken := new(internal.RefreshToken)
	if err := internal.Unmarshal(token, rToken); err != nil {
		// For backward compatibility, assume a raw refresh token ID when the
		// value does not decode (the same fallback introspection makes).
		rToken = &internal.RefreshToken{RefreshId: token}
	}

	refresh, err := h.Storage.GetRefresh(ctx, rToken.RefreshId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			h.Logger.ErrorContext(ctx, "failed to get refresh token during revocation", "err", err)
		}
		return
	}

	// RFC 7009 §2.1: only the client the token was issued to may revoke it.
	// A token held by another client is indistinguishable from an unknown one
	// in the response, so the outcome reveals nothing.
	if refresh.ClientID != client.ID {
		return
	}

	// Constant-time, like every token-secret comparison: the endpoint is
	// reachable by any authenticated client. rToken.Token is empty on the
	// raw-ID fallback, and an empty presented token must not pass the family
	// check — defense in depth, since real rows always carry a token.
	member := rToken.Token != "" &&
		(subtle.ConstantTimeCompare([]byte(refresh.Token), []byte(rToken.Token)) == 1 ||
			(refresh.ObsoleteToken != "" && subtle.ConstantTimeCompare([]byte(refresh.ObsoleteToken), []byte(rToken.Token)) == 1))
	if !member {
		return
	}

	tokens.RevokeRefreshTokenFamily(ctx, h.Storage, h.Logger, &refresh)
	h.Logger.InfoContext(ctx, "refresh token family revoked", "token_id", refresh.ID, "client_id", refresh.ClientID, "user_id", refresh.Claims.UserID)
}

// revokeAccessToken revokes what an access token stands for.
//
// Dex access tokens are stateless JWTs — there is no per-token row to delete —
// so the presented token itself keeps verifying until it expires (minutes).
// What revocation reaches is everything behind it: the refresh-token family
// its subject and client resolve to through the offline session, which is the
// same family the refresh grant rotates. With the family revoked the client
// can mint no further tokens for that authorization. A JWT that does not
// verify (foreign, expired, tampered), or that resolves to no offline session
// — a standalone refresh token leaves none — has nothing to revoke; the
// endpoint still answers 200.
func (h *Handler) revokeAccessToken(ctx context.Context, client storage.Client, token string) {
	verifier := oidc.NewVerifier(h.IssuerURL, &signer.KeySet{Signer: h.Signer}, &oidc.Config{SkipClientIDCheck: true})
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return
	}

	var claims struct {
		AuthorizingParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return
	}
	tokenClientID, err := tokens.GetClientID(idToken.Audience, claims.AuthorizingParty)
	if err != nil {
		return
	}
	// §2.1 again: only the client the token was issued to may revoke it.
	if tokenClientID != client.ID {
		return
	}

	var subject internal.IDTokenSubject
	if err := internal.Unmarshal(idToken.Subject, &subject); err != nil {
		return
	}

	offline, err := h.Storage.GetOfflineSessions(ctx, subject.UserId, subject.ConnId)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			h.Logger.ErrorContext(ctx, "failed to get offline session during access token revocation", "err", err)
		}
		return
	}
	ref, ok := offline.Refresh[client.ID]
	if !ok {
		return
	}
	refresh, err := h.Storage.GetRefresh(ctx, ref.ID)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			h.Logger.ErrorContext(ctx, "failed to get refresh token during access token revocation", "err", err)
		}
		return
	}

	tokens.RevokeRefreshTokenFamily(ctx, h.Storage, h.Logger, &refresh)
	h.Logger.InfoContext(ctx, "refresh token family revoked by access token revocation", "token_id", refresh.ID, "client_id", refresh.ClientID, "user_id", refresh.Claims.UserID)
}
