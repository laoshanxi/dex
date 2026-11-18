package connectors

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/storage"
)

// LocalConnector is the local passwordDB connector: an internal connector,
// backed by the password store, that is not part of the injected config map.
const LocalConnector = "local"

// ConnectorConfig is a configuration that can open a connector.
type ConnectorConfig interface {
	Open(id string, logger *slog.Logger) (connector.Connector, error)
}

// Resolver returns a ResolveFunc that builds the underlying implementation for a
// stored connector: the built-in local password DB (backed by storage), or a
// connector from the given config map. The map is injected by the caller so this
// package need not import any connector implementation — a library consumer can
// pass its own set of connectors.
func Resolver(store storage.Storage, logger *slog.Logger, configs map[string]func() ConnectorConfig) ResolveFunc {
	return ResolverWithPasswordLockout(store, logger, configs, nil, nil)
}

// ResolverWithPasswordLockout is Resolver serving the local password DB with
// progressive lockout: a non-nil lockout config makes every open of the local
// connector share one failure counter and persist blocked_until on the user
// identity keyed by the connector's own ID. now defaults to time.Now.
func ResolverWithPasswordLockout(store storage.Storage, logger *slog.Logger, configs map[string]func() ConnectorConfig, lockoutCfg *PasswordLockoutConfig, now func() time.Time) ResolveFunc {
	var (
		once    sync.Once
		lockout *passwordLockout
	)
	return func(conn storage.Connector) (connector.Connector, error) {
		if conn.Type == LocalConnector {
			// One lockout for every open of the connector (cache refreshes
			// included) so they share failure state. Dex has a single local
			// connector, so the first open fixes the connector ID that lock
			// state is keyed by.
			once.Do(func() {
				if lockoutCfg != nil {
					lockout = newPasswordLockout(store, *lockoutCfg, conn.ID, logger, now)
				}
			})
			return passwordDB{s: store, lockout: lockout}, nil
		}
		return openConnector(logger, configs, conn)
	}
}

// openConnector parses the stored config and opens the connector named by its type.
func openConnector(logger *slog.Logger, configs map[string]func() ConnectorConfig, conn storage.Connector) (connector.Connector, error) {
	var c connector.Connector

	f, ok := configs[conn.Type]
	if !ok {
		return c, fmt.Errorf("unknown connector type %q", conn.Type)
	}

	connConfig := f()
	if len(conn.Config) != 0 {
		if err := json.Unmarshal(conn.Config, connConfig); err != nil {
			return c, fmt.Errorf("parse connector config: %v", err)
		}
	}

	c, err := connConfig.Open(conn.ID, logger)
	if err != nil {
		return c, fmt.Errorf("failed to create connector %s: %v", conn.ID, err)
	}

	return c, nil
}
