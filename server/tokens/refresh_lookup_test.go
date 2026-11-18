package tokens

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

// seedRotatedToken stores a refresh token as it looks after one rotation: the
// current value plus the retired one in ObsoleteToken, wired into an offline
// session. withSession=false leaves the token standalone.
func seedRotatedToken(t *testing.T, s storage.Storage, withSession bool) {
	t.Helper()
	ctx := context.Background()

	now := time.Now().UTC().Round(time.Millisecond)
	require.NoError(t, s.CreateRefresh(ctx, storage.RefreshToken{
		ID:            "r1",
		Token:         "current",
		ObsoleteToken: "retired",
		ClientID:      "client-1",
		ConnectorID:   "mock",
		Claims:        storage.Claims{UserID: "u1", Username: "alice"},
		Scopes:        []string{"openid"},
		CreatedAt:     now,
		LastUsed:      now,
	}))
	if withSession {
		require.NoError(t, s.CreateOfflineSessions(ctx, storage.OfflineSessions{
			UserID:  "u1",
			ConnID:  "mock",
			Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "r1", ClientID: "client-1"}},
		}))
	}
}

// TestLookupRefreshTokenReuseRevokesFamily covers reuse detection: a token
// value a rotation already retired, presented after the reuse window closed,
// must be refused and must take the whole family — the stored row and its
// offline-session reference, current token value included — with it. Within the
// window the retired value is still answered with the current token, the grace
// a client that lost the rotated token needs.
func TestLookupRefreshTokenReuseRevokesFamily(t *testing.T) {
	t0 := time.Now()
	clientID := "client-1"

	tests := []struct {
		name        string
		withSession bool
	}{
		{"session-backed token", true},
		{"standalone token", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			logger := slog.New(slog.DiscardHandler)
			s := memory.New(logger)
			seedRotatedToken(t, s, tc.withSession)

			// Reuse window of one second; the lookup runs at t0+2s, after it closed.
			strategy := NewRefreshStrategy(true, 0, 0, time.Second, func() time.Time { return t0.Add(2 * time.Second) })
			replay := &internal.RefreshToken{RefreshId: "r1", Token: "retired"}

			_, err := LookupRefreshToken(ctx, s, strategy, logger, &clientID, replay)
			require.ErrorIs(t, err, ErrRefreshTokenReused)

			// The family is gone: neither the retired nor the current value works.
			_, err = s.GetRefresh(ctx, "r1")
			require.ErrorIs(t, err, storage.ErrNotFound)

			if tc.withSession {
				sess, err := s.GetOfflineSessions(ctx, "u1", "mock")
				require.NoError(t, err)
				require.NotContains(t, sess.Refresh, "client-1", "offline session must drop the revoked family's reference")
			}
		})
	}
}

// TestLookupRefreshTokenReuseWithinWindowKeepsFamily pins the grace: the
// retired value presented inside the reuse window is answered with the current
// token and nothing is revoked.
func TestLookupRefreshTokenReuseWithinWindowKeepsFamily(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	s := memory.New(logger)
	seedRotatedToken(t, s, true)

	strategy := NewRefreshStrategy(true, 0, 0, time.Hour, func() time.Time { return time.Now().Add(time.Minute) })
	clientID := "client-1"

	refresh, err := LookupRefreshToken(ctx, s, strategy, logger, &clientID, &internal.RefreshToken{RefreshId: "r1", Token: "retired"})
	require.NoError(t, err)
	require.Equal(t, "current", refresh.Token)

	_, err = s.GetRefresh(ctx, "r1")
	require.NoError(t, err, "reuse inside the window must not revoke the family")
}

// TestLookupRefreshTokenUnknownValueKeepsFamily: a presented value that is
// neither the current nor the retired one is not evidence of replay (it may be
// corruption, or a value several rotations old that storage no longer
// remembers), so the family is refused nothing — only the request is.
func TestLookupRefreshTokenUnknownValueKeepsFamily(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	s := memory.New(logger)
	seedRotatedToken(t, s, true)

	strategy := NewRefreshStrategy(true, 0, 0, 0, nil)
	clientID := "client-1"

	_, err := LookupRefreshToken(ctx, s, strategy, logger, &clientID, &internal.RefreshToken{RefreshId: "r1", Token: "garbage"})
	require.ErrorIs(t, err, ErrRefreshTokenInvalid)

	_, err = s.GetRefresh(ctx, "r1")
	require.NoError(t, err, "an unknown value must not revoke the family")
}
