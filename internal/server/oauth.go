package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// oauthProviders holds the server-side OAuth client credentials, read from
// the environment. A provider is active only when both ID and secret are set.
type oauthProviders struct {
	google *oauth2.Config
	github *oauth2.Config
	secret []byte // HMAC key for the access cookie
	base   string // external base URL for callbacks, e.g. https://aritun.example.com
}

// newOAuthProviders builds provider configs from environment variables:
//
//	ARITUN_OAUTH_GOOGLE_ID / ARITUN_OAUTH_GOOGLE_SECRET
//	ARITUN_OAUTH_GITHUB_ID / ARITUN_OAUTH_GITHUB_SECRET
//	ARITUN_OAUTH_SECRET     — HMAC key for the session cookie (auto-generated if unset)
//	ARITUN_OAUTH_BASE       — external base URL, e.g. https://aritun.example.com
func newOAuthProviders(base string) *oauthProviders {
	p := &oauthProviders{base: strings.TrimRight(base, "/")}
	p.secret = make([]byte, 32)
	if _, err := rand.Read(p.secret); err != nil {
		panic(err) // crypto/rand failure is not recoverable
	}

	if id, sec := envSecret("ARITUN_OAUTH_GOOGLE_ID"), envSecret("ARITUN_OAUTH_GOOGLE_SECRET"); id != "" && sec != "" {
		p.google = &oauth2.Config{
			ClientID:     id,
			ClientSecret: sec,
			Endpoint:     google.Endpoint,
			RedirectURL:  p.callbackURL("google"),
			Scopes:       []string{"openid", "email", "profile"},
		}
	}
	if id, sec := envSecret("ARITUN_OAUTH_GITHUB_ID"), envSecret("ARITUN_OAUTH_GITHUB_SECRET"); id != "" && sec != "" {
		p.github = &oauth2.Config{
			ClientID:     id,
			ClientSecret: sec,
			Endpoint:     github.Endpoint,
			RedirectURL:  p.callbackURL("github"),
			Scopes:       []string{"read:user", "user:email"},
		}
	}
	return p
}

func (p *oauthProviders) callbackURL(provider string) string {
	base := p.base
	if base == "" {
		base = "http://localhost:9090" // dev fallback; real deploys set ARITUN_OAUTH_BASE
	}
	return base + oauthCallbackPath + provider
}

func (p *oauthProviders) ready(provider string) bool {
	switch provider {
	case "google":
		return p.google != nil
	case "github":
		return p.github != nil
	}
	return false
}

func (p *oauthProviders) config(provider string) *oauth2.Config {
	switch provider {
	case "google":
		return p.google
	case "github":
		return p.github
	}
	return nil
}

// startLogin redirects the visitor to the provider's consent screen. The
// tunnel subdomain rides along in the state so the callback knows where to
// send the authenticated user.
func (p *oauthProviders) startLogin(w http.ResponseWriter, r *http.Request, provider, subdomain string) {
	cfg := p.config(provider)
	if cfg == nil {
		http.Error(w, "oauth provider not configured", http.StatusBadGateway)
		return
	}
	state := p.signState(subdomain)
	authURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback exchanges the code for a token, verifies the state, then
// sets a signed cookie and redirects back to the tunnel.
func (p *oauthProviders) handleCallback(w http.ResponseWriter, r *http.Request, provider string) {
	cfg := p.config(provider)
	if cfg == nil {
		http.Error(w, "oauth provider not configured", http.StatusBadGateway)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "oauth error: "+e, http.StatusForbidden)
		return
	}
	state := q.Get("state")
	subdomain, ok := p.verifyState(state)
	if !ok {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	tok, err := cfg.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	// Pull the user's identity so the dashboard/inspector can show it.
	identity := p.fetchIdentity(r.Context(), provider, tok)
	if identity == "" {
		identity = "user"
	}

	cookieValue := p.signCookie(subdomain, identity, time.Now().Add(24*time.Hour))
	http.SetCookie(w, &http.Cookie{
		Name:     oauthCookieName(subdomain),
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure when the external base is https.
		Secure: strings.HasPrefix(p.base, "https://"),
	})
	http.Redirect(w, r, p.tunnelURL(subdomain), http.StatusFound)
}

// tunnelURL rebuilds "scheme://sub.parentDomain/" from the configured base.
func (p *oauthProviders) tunnelURL(subdomain string) string {
	u, err := url.Parse(p.base)
	if err != nil || u.Host == "" {
		return "https://" + subdomain + "/"
	}
	return u.Scheme + "://" + subdomain + "." + u.Host + "/"
}

func (p *oauthProviders) fetchIdentity(ctx context.Context, provider string, tok *oauth2.Token) string {
	cfg := p.config(provider)
	if cfg == nil {
		return ""
	}
	client := cfg.Client(ctx, tok)
	var endpoint string
	switch provider {
	case "google":
		endpoint = "https://www.googleapis.com/oauth2/v2/userinfo"
	case "github":
		endpoint = "https://api.github.com/user"
	default:
		return ""
	}
	resp, err := client.Get(endpoint)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var payload struct {
		Email string `json:"email"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	if payload.Email != "" {
		return payload.Email
	}
	if payload.Login != "" {
		return payload.Login
	}
	return payload.Name
}

// signState binds a subdomain to an HMAC so a forged callback cannot mint a
// cookie for an arbitrary tunnel.
func (p *oauthProviders) signState(subdomain string) string {
	exp := time.Now().Add(15 * time.Minute).Unix()
	payload := fmt.Sprintf("%s|%d", subdomain, exp)
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func (p *oauthProviders) verifyState(state string) (string, bool) {
	i := strings.LastIndexByte(state, '.')
	if i < 0 {
		return "", false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(state[:i])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(state[i+1:])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, p.secret)
	mac.Write(rawPayload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	parts := strings.Split(string(rawPayload), "|")
	if len(parts) != 2 {
		return "", false
	}
	var exp int64
	if _, err := fmt.Sscanf(parts[1], "%d", &exp); err != nil {
		return "", false
	}
	if time.Now().Unix() > exp {
		return "", false
	}
	return parts[0], true
}

// signCookie builds "<subdomain>.<expiry>.<identity>.<hmac>".
func (p *oauthProviders) signCookie(subdomain, identity string, expiry time.Time) string {
	payload := fmt.Sprintf("%s|%d|%s", subdomain, expiry.Unix(), identity)
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// verifyCookie checks a cookie value and returns the identity if valid and
// unexpired for the given subdomain.
func (p *oauthProviders) verifyCookie(subdomain, value string) (string, bool) {
	i := strings.LastIndexByte(value, '.')
	if i < 0 {
		return "", false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(value[:i])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(value[i+1:])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, p.secret)
	mac.Write(rawPayload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	parts := strings.SplitN(string(rawPayload), "|", 3)
	if len(parts) != 3 {
		return "", false
	}
	if parts[0] != subdomain {
		return "", false
	}
	var exp int64
	if _, err := fmt.Sscanf(parts[1], "%d", &exp); err != nil {
		return "", false
	}
	if time.Now().Unix() > exp {
		return "", false
	}
	return parts[2], true
}

const (
	oauthCallbackPath = "/-/auth/callback/"
)

func oauthCookieName(sub string) string {
	sum := sha256.Sum256([]byte(sub))
	return "aritun_auth_" + fmt.Sprintf("%x", sum[:8])
}

func envSecret(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
