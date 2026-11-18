package home

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

func TestSessionExpiry(t *testing.T) {
	absolute := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		session  storage.AuthSession
		want     time.Time
		wantIdle bool
	}{
		{
			name:     "idle first",
			session:  storage.AuthSession{AbsoluteExpiry: absolute, IdleExpiry: absolute.Add(-time.Hour)},
			want:     absolute.Add(-time.Hour),
			wantIdle: true,
		},
		{
			name:     "absolute first",
			session:  storage.AuthSession{AbsoluteExpiry: absolute, IdleExpiry: absolute.Add(time.Hour)},
			want:     absolute,
			wantIdle: false,
		},
		{
			// Equal deadlines are the absolute one: it cannot move, so it is the
			// honest label of the two.
			name:     "equal",
			session:  storage.AuthSession{AbsoluteExpiry: absolute, IdleExpiry: absolute},
			want:     absolute,
			wantIdle: false,
		},
		{
			name:     "only idle set",
			session:  storage.AuthSession{IdleExpiry: absolute},
			want:     absolute,
			wantIdle: true,
		},
		{
			name:     "only absolute set",
			session:  storage.AuthSession{AbsoluteExpiry: absolute},
			want:     absolute,
			wantIdle: false,
		},
		{
			name:    "neither set",
			session: storage.AuthSession{},
			want:    time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, idle := sessionExpiry(&tc.session)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantIdle, idle)
		})
	}
}

func TestTimeFields(t *testing.T) {
	iso, text := timeFields(time.Date(2026, 7, 28, 9, 5, 0, 0, time.UTC))
	// The attribute has to parse as a date/time for <time> to mean anything.
	assert.Equal(t, "2026-07-28T09:05:00Z", iso)
	assert.Equal(t, "28 Jul 2026, 09:05 UTC", text)

	// A different zone is still reported as the same instant in UTC.
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	assert.NoError(t, err)
	iso, text = timeFields(time.Date(2026, 7, 28, 18, 5, 0, 0, tokyo))
	assert.Equal(t, "2026-07-28T09:05:00Z", iso)
	assert.Equal(t, "28 Jul 2026, 09:05 UTC", text)

	iso, text = timeFields(time.Time{})
	assert.Empty(t, iso)
	assert.Empty(t, text)
}

// TestHandleInlineSecurityHeaders: the inline fallback page carries the same
// browser-hardening headers as every other HTML page dex serves.
func TestHandleInlineSecurityHeaders(t *testing.T) {
	h := &Handler{
		IssuerURL: oauth2.IssuerURL{URL: url.URL{Scheme: "https", Host: "dex.example.com", Path: "/dex"}},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	h.handleInline(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
}
