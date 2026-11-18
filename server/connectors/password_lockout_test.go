package connectors

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/passwords"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

// lockoutFixture is a passwordDB with lockout over a memory store and a
// controllable clock, plus one seeded user.
type lockoutFixture struct {
	t     *testing.T
	db    passwordDB
	store storage.Storage
	logs  *bytes.Buffer
	clock *time.Time
}

func newLockoutFixture(t *testing.T, cfg PasswordLockoutConfig) *lockoutFixture {
	t.Helper()

	t0 := time.Now().UTC()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := memory.New(logger)
	lockout := newPasswordLockout(store, cfg, "local", logger, func() time.Time { return t0 })

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, store.CreatePassword(t.Context(), storage.Password{
		Email:  "jane@example.com",
		UserID: "jane",
		Hash:   hash,
	}))

	return &lockoutFixture{
		t:     t,
		db:    passwordDB{s: store, lockout: lockout},
		store: store,
		logs:  logs,
		clock: &t0,
	}
}

func (f *lockoutFixture) login(password string) bool {
	_, ok, err := f.db.Login(f.t.Context(), connector.Scopes{}, "jane@example.com", password)
	require.NoError(f.t, err)
	return ok
}

func (f *lockoutFixture) blockedUntil() time.Time {
	ui, err := f.store.GetUserIdentity(f.t.Context(), "jane", "local")
	if err != nil {
		require.ErrorIs(f.t, err, storage.ErrNotFound)
		return time.Time{} // no identity row yet: never locked
	}
	return ui.BlockedUntil
}

func TestPasswordLockoutLocksAndLifts(t *testing.T) {
	f := newLockoutFixture(t, PasswordLockoutConfig{Threshold: 5, Duration: 15 * time.Minute, MaxDuration: 24 * time.Hour})

	// Threshold minus one failures leave the account usable.
	for i := 0; i < 4; i++ {
		require.False(t, f.login("wrong"))
	}
	require.True(t, f.login("secret"))
	require.True(t, f.blockedUntil().IsZero(), "no lock before the threshold")

	// The threshold failure locks for the base duration.
	for i := 0; i < 5; i++ {
		require.False(t, f.login("wrong"))
	}
	require.WithinDuration(t, f.clock.Add(15*time.Minute), f.blockedUntil(), time.Second)
	require.False(t, f.login("secret"), "locked account refuses the correct password")

	// The lock lifts once blocked_until passes.
	*f.clock = f.clock.Add(16 * time.Minute)
	require.True(t, f.login("secret"))
	require.True(t, f.blockedUntil().IsZero(), "a successful login clears the lock")

	require.Contains(t, f.logs.String(), "password login failed", "failures must be logged")
	require.Contains(t, f.logs.String(), "jane@example.com", "failure logs carry the email")
	require.Contains(t, f.logs.String(), "password account locked", "the lock itself must be logged")
	require.NotContains(t, f.logs.String(), "secret", "the password must never appear in the logs")
}

func TestPasswordLockoutEscalates(t *testing.T) {
	f := newLockoutFixture(t, PasswordLockoutConfig{Threshold: 5, Duration: 15 * time.Minute, MaxDuration: 45 * time.Minute})

	// Each further threshold-crossing doubles the lock, capped at MaxDuration.
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, 45 * time.Minute, 45 * time.Minute}
	for i, w := range want {
		for j := 0; j < 5; j++ {
			require.False(t, f.login("wrong"), "failure %d.%d", i, j)
		}
		require.WithinDuration(t, f.clock.Add(w), f.blockedUntil(), time.Second,
			"lock %d should be %s", i+1, w)
	}
}

// TestPasswordLockoutSurvivesRestart: a lock persisted by one process instance
// is enforced by a fresh one whose in-memory count starts at zero.
func TestPasswordLockoutSurvivesRestart(t *testing.T) {
	f := newLockoutFixture(t, PasswordLockoutConfig{Threshold: 2, Duration: time.Hour})

	for i := 0; i < 2; i++ {
		require.False(t, f.login("wrong"))
	}
	require.False(t, f.login("secret"), "locked by the first instance")

	restarted := passwordDB{s: f.store,
		lockout: newPasswordLockout(f.store, PasswordLockoutConfig{Threshold: 2, Duration: time.Hour}, "local",
			slog.New(slog.DiscardHandler), func() time.Time { return *f.clock })}
	_, ok, err := restarted.Login(t.Context(), connector.Scopes{}, "jane@example.com", "secret")
	require.NoError(t, err)
	require.False(t, ok, "a fresh instance must honor the persisted blocked_until")

	*f.clock = f.clock.Add(61 * time.Minute)
	_, ok, err = restarted.Login(t.Context(), connector.Scopes{}, "jane@example.com", "secret")
	require.NoError(t, err)
	require.True(t, ok, "the lock lifts once blocked_until passes")
}

// TestPasswordLockoutUnknownEmail: failures against an unknown email are
// counted (and logged) but create no user identity — there is nothing to
// persist a lock on.
func TestPasswordLockoutUnknownEmail(t *testing.T) {
	f := newLockoutFixture(t, PasswordLockoutConfig{Threshold: 3, Duration: time.Hour})

	for i := 0; i < 3; i++ {
		_, ok, err := f.db.Login(t.Context(), connector.Scopes{}, "ghost@example.com", "wrong")
		require.NoError(t, err)
		require.False(t, ok)
	}
	_, err := f.store.GetUserIdentity(t.Context(), "jane", "local")
	require.ErrorIs(t, err, storage.ErrNotFound, "no identity row must be created for unknown emails")

	require.Contains(t, f.logs.String(), "password login failed", "failures must be logged")
	require.Contains(t, f.logs.String(), "ghost@example.com", "unknown-email failures are logged for monitoring")
	require.NotContains(t, f.logs.String(), "secret", "the password must never appear in the logs")
}

// TestPasswordLockoutDisabledByNilConnector: the connector without a lockout
// keeps serving every failure (mirrors NewPasswordDB).
func TestPasswordLockoutDisabledByNilConnector(t *testing.T) {
	f := newLockoutFixture(t, PasswordLockoutConfig{Threshold: 1, Duration: time.Hour})
	f.db.lockout = nil

	for i := 0; i < 5; i++ {
		require.False(t, f.login("wrong"))
	}
	require.True(t, f.login("secret"), "without lockout the correct password works immediately")
}

func TestPasswordLockoutConfigDefaults(t *testing.T) {
	got := PasswordLockoutConfig{}.WithDefaults()
	require.Equal(t, PasswordLockoutConfig{
		Threshold:   defaultLockoutThreshold,
		Duration:    defaultLockoutDuration,
		MaxDuration: defaultLockoutMaxDuration,
	}, got)
}

// TestPasswordDBUnknownUserRunsBcrypt: the unknown-email path must run a full
// bcrypt comparison, like a wrong password does, or the response time alone
// would reveal whether an account exists. A cost-10 bcrypt is tens of
// milliseconds; a path that skipped it is well under this bound.
func TestPasswordDBUnknownUserRunsBcrypt(t *testing.T) {
	f := newLockoutFixture(t, PasswordLockoutConfig{Threshold: 100, Duration: time.Hour})
	f.db.lockout = nil // time the comparison itself, not lockout bookkeeping

	start := time.Now()
	_, ok, err := f.db.Login(t.Context(), connector.Scopes{}, "ghost@example.com", "wrong")
	require.NoError(t, err)
	require.False(t, ok)
	unknown := time.Since(start)

	start = time.Now()
	require.False(t, f.login("wrong"))
	wrongPassword := time.Since(start)

	require.Greater(t, unknown, 10*time.Millisecond, "unknown-email login must run a bcrypt comparison")
	require.Greater(t, wrongPassword, 10*time.Millisecond, "wrong-password login runs a bcrypt comparison")
}

// TestDummyPasswordHashCost pins the dummy hash to the minimum accepted cost:
// the constant must never drift below what CheckCost enforces for real users.
func TestDummyPasswordHashCost(t *testing.T) {
	require.NoError(t, passwords.CheckCost(dummyPasswordHash))

	cost, err := bcrypt.Cost(dummyPasswordHash)
	require.NoError(t, err)
	require.Equal(t, bcrypt.DefaultCost, cost)

	// The dummy hash must not verify any password a test user could have.
	require.Error(t, bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte("secret")))
}
