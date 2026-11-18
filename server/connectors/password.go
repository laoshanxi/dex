package connectors

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/passwords"
	"github.com/dexidp/dex/storage"
)

// Defaults for the local password lockout. They are deliberately conservative:
// five failures lock an account for fifteen minutes, enough to make online
// spraying impractical without locking out a mistyping human for long.
const (
	defaultLockoutThreshold   = 5
	defaultLockoutDuration    = 15 * time.Minute
	defaultLockoutMaxDuration = 24 * time.Hour
)

// PasswordLockoutConfig configures progressive temporary lockout for the local
// password connector. After Threshold consecutive failed logins the account is
// written a blocked_until on its user identity and refused (with the same
// generic error as a wrong password) until that moment passes. The lock grows
// with every further Threshold failures, capped at MaxDuration. Zero fields
// take the defaults above.
type PasswordLockoutConfig struct {
	Threshold   int
	Duration    time.Duration
	MaxDuration time.Duration
}

// WithDefaults returns the config with unset (or non-positive) fields replaced
// by their defaults.
func (c PasswordLockoutConfig) WithDefaults() PasswordLockoutConfig {
	if c.Threshold <= 0 {
		c.Threshold = defaultLockoutThreshold
	}
	if c.Duration <= 0 {
		c.Duration = defaultLockoutDuration
	}
	if c.MaxDuration <= 0 {
		c.MaxDuration = defaultLockoutMaxDuration
	}
	return c
}

// dummyPasswordHash is a fixed bcrypt hash (cost 10, bcrypt.DefaultCost and the
// minimum CheckCost accepts) of an unusable password. An unknown email is
// compared against it so that "no such user" costs the same bcrypt run as a
// wrong password, and the login response time alone cannot enumerate accounts.
// It matches no real hash a client could ever log in with. Cost 10 is the lower
// bound of the 10–16 range CheckCost accepts, and bcrypt scales as 2^cost, so a
// high-cost deployment keeps a timing residue of up to 64x at cost 16 (4x at the
// recommended 12) — versus 80x without the dummy.
var dummyPasswordHash = []byte("$2a$10$3J9/DX0rz/ZkD3WRcNxJFeFPcmB/Yi0yt7jS6quW7WUUJtuoa67Qy")

// NewPasswordDB returns the built-in local password connector backed by the
// password store. Resolver uses it for LocalConnector; it is exported so a
// custom ResolveFunc can reuse it. Lockout is disabled; the resolver built by
// ResolverWithPasswordLockout serves it with one.
func NewPasswordDB(s storage.Storage) interface {
	connector.Connector
	connector.PasswordConnector
} {
	return passwordDB{s: s}
}

type passwordDB struct {
	s storage.Storage

	// lockout counts failed logins and enforces blocked_until. nil disables it.
	lockout *passwordLockout
}

func resolvePasswordName(p storage.Password) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Username
}

func resolvePasswordEmailVerified(p storage.Password) bool {
	if p.EmailVerified != nil {
		return *p.EmailVerified
	}
	return true
}

func (db passwordDB) Login(ctx context.Context, s connector.Scopes, email, password string) (connector.Identity, bool, error) {
	p, err := db.s.GetPassword(ctx, email)
	if err != nil {
		if err != storage.ErrNotFound {
			return connector.Identity{}, false, fmt.Errorf("get password: %v", err)
		}
		// Run the same bcrypt comparison a wrong password would run, against a
		// dummy hash, so the response time does not reveal whether the account
		// exists. The result is deliberately ignored.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
		// Count the attempt so spraying unknown emails is throttled too; there is
		// just no account to persist a lock on.
		if db.lockout != nil {
			db.lockout.recordFailure(ctx, email, nil)
		}
		return connector.Identity{}, false, nil
	}
	// This check prevents dex users from logging in using static passwords
	// configured with hash costs that are too high or low.
	if err := passwords.CheckCost(p.Hash); err != nil {
		return connector.Identity{}, false, err
	}
	if db.lockout != nil && db.lockout.blocked(ctx, p) {
		// Keep counting while blocked so a sustained spray ratchets the lock up.
		// The answer stays the generic wrong-password refusal either way.
		db.lockout.recordFailure(ctx, p.Email, &p)
		return connector.Identity{}, false, nil
	}
	if err := bcrypt.CompareHashAndPassword(p.Hash, []byte(password)); err != nil {
		if db.lockout != nil {
			db.lockout.recordFailure(ctx, p.Email, &p)
		}
		return connector.Identity{}, false, nil
	}
	if db.lockout != nil {
		db.lockout.reset(ctx, p)
	}
	return connector.Identity{
		UserID:            p.UserID,
		Username:          resolvePasswordName(p),
		PreferredUsername: p.PreferredUsername,
		Email:             p.Email,
		EmailVerified:     resolvePasswordEmailVerified(p),
		Groups:            p.Groups,
	}, true, nil
}

func (db passwordDB) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	// If the user has been deleted, the refresh token will be rejected.
	p, err := db.s.GetPassword(ctx, identity.Email)
	if err != nil {
		if err == storage.ErrNotFound {
			return connector.Identity{}, fmt.Errorf("user not found: %w", connector.ErrUserRevoked)
		}
		return connector.Identity{}, fmt.Errorf("get password: %v", err)
	}

	// User removed but a new user with the same email exists.
	if p.UserID != identity.UserID {
		return connector.Identity{}, fmt.Errorf("user not found: %w", connector.ErrUserRevoked)
	}

	// If a user has updated their username, that will be reflected in the
	// refreshed token.
	//
	// No other fields are expected to be refreshable as email is effectively used
	// as an ID.
	identity.Username = resolvePasswordName(p)
	identity.PreferredUsername = p.PreferredUsername
	identity.EmailVerified = resolvePasswordEmailVerified(p)
	identity.Groups = p.Groups

	return identity, nil
}

func (db passwordDB) Prompt() string {
	return "Email Address"
}

// passwordLockout is the shared failure state of the local password connector:
// consecutive failures per account in memory, and the resulting blocked_until
// on the account's user identity so a lock outlives a restart. One instance is
// shared by every open of the connector, so the count survives cache refreshes.
type passwordLockout struct {
	s           storage.Storage
	cfg         PasswordLockoutConfig
	connectorID string
	logger      *slog.Logger
	now         func() time.Time

	mu       sync.Mutex
	failures map[string]*failureState // lowercased email -> consecutive failures
}

// failureState is one account's in-memory failure count and, once the count
// has crossed the threshold, when that lock expires.
type failureState struct {
	count       int
	lockedUntil time.Time
}

func newPasswordLockout(s storage.Storage, cfg PasswordLockoutConfig, connectorID string, logger *slog.Logger, now func() time.Time) *passwordLockout {
	if now == nil {
		now = time.Now
	}
	return &passwordLockout{
		s:           s,
		cfg:         cfg.WithDefaults(),
		connectorID: connectorID,
		logger:      logger,
		now:         now,
		failures:    make(map[string]*failureState),
	}
}

// blocked reports whether the account is currently locked. The persisted
// blocked_until is what survives a restart; the in-memory expiry covers a
// count that crossed the threshold before its lock write landed, or when the
// write failed. Unknown emails never reach a lock: there is no account to
// persist one on.
func (l *passwordLockout) blocked(ctx context.Context, p storage.Password) bool {
	now := l.now()

	l.mu.Lock()
	st := l.failures[strings.ToLower(p.Email)]
	lockedUntil := time.Time{}
	if st != nil {
		lockedUntil = st.lockedUntil
	}
	l.mu.Unlock()
	if lockedUntil.After(now) {
		return true
	}

	ui, err := l.s.GetUserIdentity(ctx, p.UserID, l.connectorID)
	if err != nil {
		// Unreadable lock state must not lock the account out (a broken read is
		// an availability problem, not an attack signal); the in-memory expiry
		// still bounds failures within this process.
		if err != storage.ErrNotFound {
			l.logger.ErrorContext(ctx, "failed to read account lock state", "user_id", p.UserID, "err", err)
		}
		return false
	}
	return ui.BlockedUntil.After(now)
}

// recordFailure bumps the consecutive-failure count for the account and, each
// time the count crosses a multiple of the threshold, persists a new
// blocked_until. p is nil for an unknown email: counted, never locked.
func (l *passwordLockout) recordFailure(ctx context.Context, email string, p *storage.Password) {
	var until time.Time
	count := 0

	l.mu.Lock()
	st := l.failures[strings.ToLower(email)]
	if st == nil {
		st = &failureState{}
		l.failures[strings.ToLower(email)] = st
	}
	st.count++
	count = st.count
	// Record the lock in the same critical section as the count it follows: a
	// concurrent successful login then either sees the lock and is refused, or
	// resets a count that had not locked anything yet.
	if p != nil && count%l.cfg.Threshold == 0 {
		until = l.now().Add(l.lockDuration(count))
		st.lockedUntil = until
	}
	l.mu.Unlock()

	l.logger.WarnContext(ctx, "password login failed", "email", email, "failures", count)

	if until.IsZero() {
		return
	}

	if l.persistBlockedUntil(ctx, *p, until) {
		l.logger.WarnContext(ctx, "password account locked",
			"email", p.Email, "user_id", p.UserID, "failures", count, "blocked_until", until)
	}
}

// reset clears the failure count after a successful login and lifts a lock that
// has already expired, leaving a clean row behind.
func (l *passwordLockout) reset(ctx context.Context, p storage.Password) {
	l.mu.Lock()
	delete(l.failures, strings.ToLower(p.Email))
	l.mu.Unlock()

	ui, err := l.s.GetUserIdentity(ctx, p.UserID, l.connectorID)
	if err != nil || ui.BlockedUntil.IsZero() {
		return
	}
	// Unlike the ratchet in persistBlockedUntil, a successful login lifts the
	// lock outright, whatever it was set to.
	if err := l.s.UpdateUserIdentity(ctx, p.UserID, l.connectorID, func(old storage.UserIdentity) (storage.UserIdentity, error) {
		old.BlockedUntil = time.Time{}
		return old, nil
	}); err != nil {
		l.logger.ErrorContext(ctx, "failed to lift account lock", "user_id", p.UserID, "err", err)
	}
}

// lockDuration escalates with the failure count: the base duration at the
// threshold, doubling for every further multiple of it, capped at MaxDuration.
func (l *passwordLockout) lockDuration(count int) time.Duration {
	d := l.cfg.Duration
	for escalations := count/l.cfg.Threshold - 1; escalations > 0; escalations-- {
		if d >= l.cfg.MaxDuration {
			return l.cfg.MaxDuration
		}
		next := d * 2
		if next < d { // overflow guard.
			return l.cfg.MaxDuration
		}
		d = next
	}
	if d > l.cfg.MaxDuration {
		return l.cfg.MaxDuration
	}
	return d
}

// persistBlockedUntil writes blocked_until on the account's user identity,
// creating the row (with the password record's claims) when the account has
// never logged in. It reports whether the write went through; failures are
// logged and otherwise ignored — the in-memory count still holds within this
// process. An existing later blocked_until is never shortened.
func (l *passwordLockout) persistBlockedUntil(ctx context.Context, p storage.Password, until time.Time) bool {
	_, err := l.s.GetUserIdentity(ctx, p.UserID, l.connectorID)
	switch {
	case err == storage.ErrNotFound:
		ui := storage.UserIdentity{
			UserID:      p.UserID,
			ConnectorID: l.connectorID,
			Claims: storage.Claims{
				UserID:            p.UserID,
				Username:          resolvePasswordName(p),
				PreferredUsername: p.PreferredUsername,
				Email:             p.Email,
				EmailVerified:     resolvePasswordEmailVerified(p),
				Groups:            p.Groups,
			},
			Consents:     make(map[string][]string),
			CreatedAt:    l.now(),
			BlockedUntil: until,
		}
		if err := l.s.CreateUserIdentity(ctx, ui); err != nil {
			l.logger.ErrorContext(ctx, "failed to persist account lock", "user_id", p.UserID, "err", err)
			return false
		}
		return true
	case err != nil:
		l.logger.ErrorContext(ctx, "failed to read user identity before locking", "user_id", p.UserID, "err", err)
		return false
	}

	if err := l.s.UpdateUserIdentity(ctx, p.UserID, l.connectorID, func(old storage.UserIdentity) (storage.UserIdentity, error) {
		if old.BlockedUntil.After(until) {
			return old, nil
		}
		old.BlockedUntil = until
		return old, nil
	}); err != nil {
		l.logger.ErrorContext(ctx, "failed to persist account lock", "user_id", p.UserID, "err", err)
		return false
	}
	return true
}
