package templates

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/dexidp/dex/web"
)

func TestRelativeURL(t *testing.T) {
	tests := []struct {
		name       string
		serverPath string
		reqPath    string
		assetPath  string
		expected   string
	}{
		{
			name:       "server-root-req-one-level-asset-two-level",
			serverPath: "/",
			reqPath:    "/auth",
			assetPath:  "/theme/main.css",
			expected:   "theme/main.css",
		},
		{
			name:       "server-one-level-req-one-level-asset-two-level",
			serverPath: "/dex",
			reqPath:    "/dex/auth",
			assetPath:  "/theme/main.css",
			expected:   "theme/main.css",
		},
		{
			name:       "server-root-req-two-level-asset-three-level",
			serverPath: "/dex",
			reqPath:    "/dex/auth/connector",
			assetPath:  "assets/css/main.css",
			expected:   "../assets/css/main.css",
		},
		{
			name:       "server-root-page",
			serverPath: "/dex",
			reqPath:    "/dex",
			assetPath:  "static/main.css",
			expected:   "dex/static/main.css",
		},
		{
			name:       "server-root-page-nested",
			serverPath: "/dex/idp",
			reqPath:    "/dex/idp",
			assetPath:  "theme/styles.css",
			expected:   "dex/idp/theme/styles.css",
		},
		{
			name:       "server-root-no-subpath",
			serverPath: "/",
			reqPath:    "/",
			assetPath:  "static/main.css",
			expected:   "static/main.css",
		},
		{
			name:       "external-url",
			serverPath: "/dex",
			reqPath:    "/dex/auth/connector",
			assetPath:  "https://kubernetes.io/images/favicon.png",
			expected:   "https://kubernetes.io/images/favicon.png",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := relativeURL(test.serverPath, test.reqPath, test.assetPath)
			if actual != test.expected {
				t.Fatalf("Got '%s'. Expected '%s'", actual, test.expected)
			}
		})
	}
}

func TestSortConnectors(t *testing.T) {
	connectors := []ConnectorInfo{
		{ID: "keycloak", Name: "keycloak"},
		{ID: "okta", Name: "Okta"},
		{ID: "azure", Name: "azure ad"},
		{ID: "google", Name: "Google"},
	}

	sortConnectors(connectors)

	// Byte order would have put both lowercase names below both capitalised
	// ones, which is a property of ASCII rather than of anything the operator
	// meant by naming a connector.
	expected := []string{"azure ad", "Google", "keycloak", "Okta"}
	for i, name := range expected {
		if connectors[i].Name != name {
			t.Fatalf("position %d: got %q, expected %q", i, connectors[i].Name, name)
		}
	}
}

func TestSortConnectorsKeepsCaseVariantsStable(t *testing.T) {
	connectors := []ConnectorInfo{
		{ID: "second", Name: "SSO"},
		{ID: "first", Name: "sso"},
	}

	sortConnectors(connectors)

	if connectors[0].ID != "second" || connectors[1].ID != "first" {
		t.Fatalf("names differing only in case were reordered: %q, %q", connectors[0].ID, connectors[1].ID)
	}
}

// newTestTemplates loads the bundled web assets once for the security-header
// tests.
func newTestTemplates(t *testing.T) *Templates {
	t.Helper()
	_, _, _, tmpls, err := LoadWebConfig(Config{
		WebFS:     web.FS(),
		Issuer:    "dex",
		IssuerURL: "https://dex.example.com",
	})
	if err != nil {
		t.Fatalf("load web config: %v", err)
	}
	return tmpls
}

// TestRenderedPagesCarrySecurityHeaders: every HTML page dex renders must
// carry the default hardening headers — no MIME sniffing, no framing, no
// caching — and the default CSP.
func TestRenderedPagesCarrySecurityHeaders(t *testing.T) {
	tmpls := newTestTemplates(t)
	r := httptest.NewRequest("GET", "/auth/local/login", nil)

	render := map[string]func(w http.ResponseWriter){
		"login": func(w http.ResponseWriter) { tmpls.Login(r, w, nil) },
		"password": func(w http.ResponseWriter) {
			tmpls.Password(r, w, "/auth/local/login", "", "Email Address", false, "", nil)
		},
		"approval":  func(w http.ResponseWriter) { tmpls.Approval(r, w, "reqid", "jane", "dex client", []string{"openid"}) },
		"home":      func(w http.ResponseWriter) { tmpls.Home(r, w, HomeData{LoggedIn: true}) },
		"error":     func(w http.ResponseWriter) { tmpls.Err(r, w, 400, "bad") },
		"logout":    func(w http.ResponseWriter) { tmpls.Logout(r, w, "/", true, true) },
		"device":    func(w http.ResponseWriter) { tmpls.Device(r, w, "/device", "", false) },
		"totp":      func(w http.ResponseWriter) { tmpls.TOTPVerify(r, w, "/totp", "dex", "local", "qr==", false) },
		"webauthn":  func(w http.ResponseWriter) { tmpls.WebAuthnVerify(r, w, "login", "id") },
		"oob":       func(w http.ResponseWriter) { tmpls.OOB(r, w, "code") },
		"devicesuc": func(w http.ResponseWriter) { tmpls.DeviceSuccess(r, w, "client") },
	}

	for name, fn := range render {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			fn(w)
			resp := w.Result()
			for header, want := range map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
				"Cache-Control":           "no-store",
				"Content-Security-Policy": contentSecurityPolicy,
			} {
				if got := resp.Header.Get(header); got != want {
					t.Errorf("%s: %s = %q, want %q", name, header, got, want)
				}
			}
		})
	}
}

// TestSetSecurityHeadersKeepsOperatorValues: a header the operator already set
// through the router's response headers must win over the default.
func TestSetSecurityHeadersKeepsOperatorValues(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	SetSecurityHeaders(w, "")
	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Errorf("operator CSP clobbered: %q", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

// TestContentSecurityPolicyPinsRenderedScripts: every inline script a rendered
// page carries must be pinned by hash in the default CSP, or the page breaks
// in every enforcing browser. The webauthn page interpolates the mode into its
// script, so both renderings are checked.
func TestContentSecurityPolicyPinsRenderedScripts(t *testing.T) {
	tmpls := newTestTemplates(t)
	r := httptest.NewRequest("GET", "/", nil)

	pages := map[string]string{}
	get := func(name string, fn func(w http.ResponseWriter)) string {
		w := httptest.NewRecorder()
		fn(w)
		pages[name] = w.Body.String()
		return pages[name]
	}
	get("password", func(w http.ResponseWriter) { tmpls.Password(r, w, "/login", "", "Email Address", false, "", nil) })
	get("home", func(w http.ResponseWriter) { tmpls.Home(r, w, HomeData{LoggedIn: true}) })
	get("webauthn-register", func(w http.ResponseWriter) { tmpls.WebAuthnVerify(r, w, "register", "id") })
	get("webauthn-login", func(w http.ResponseWriter) { tmpls.WebAuthnVerify(r, w, "login", "id") })

	re := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	for name, body := range pages {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			sum := sha256.Sum256([]byte(m[1]))
			hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			if !strings.Contains(contentSecurityPolicy, hash) {
				t.Errorf("%s: rendered script (%q...) hash %s is not pinned by the default CSP", name, m[1][:min(40, len(m[1]))], hash)
			}
		}
	}

	// The WebAuthn button's onclick attribute is pinned the same way, which is
	// why the policy carries 'unsafe-hashes'.
	sum := sha256.Sum256([]byte("startWebAuthn()"))
	onclickHash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	if !strings.Contains(contentSecurityPolicy, onclickHash) {
		t.Errorf("onclick handler hash %s is not pinned by the default CSP", onclickHash)
	}
	if !strings.Contains(contentSecurityPolicy, "'unsafe-hashes'") {
		t.Error("policy must carry 'unsafe-hashes' for the pinned onclick attribute")
	}
}
