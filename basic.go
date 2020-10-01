package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/GehirnInc/crypt"

	// Import all crypters supported
	_ "github.com/GehirnInc/crypt/apr1_crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
)

type compareFunc func(hashedPassword, password []byte) error

var (
	errMismatchedHashAndPassword = errors.New("mismatched hash and password")
)

// BasicAuth is an authenticator implementation for 'Basic' HTTP
// Authentication scheme (RFC 7617).
type BasicAuth struct {
	Realm   string
	Secrets SecretProvider
	// Headers used by authenticator. Set to ProxyHeaders to use with
	// proxy server. When nil, NormalHeaders are used.
	Headers *Headers
}

// check that BasicAuth implements AuthenticatorInterface
var _ = (AuthenticatorInterface)((*BasicAuth)(nil))

// CheckAuth checks the username/password combination from the
// request. Returns either an empty string (authentication failed) or
// the name of the authenticated user.
func (a *BasicAuth) CheckAuth(r *http.Request) string {
	user, password, ok := r.BasicAuth()
	if !ok {
		return ""
	}

	secret := a.Secrets(user, a.Realm)
	if secret == "" {
		return ""
	}

	if !CheckSecret(password, secret) {
		return ""
	}

	return user
}

// CheckSecret returns true if the password matches the encrypted
// secret.
func CheckSecret(password, secret string) bool {
	if !crypt.IsHashSupported(secret) {
		return false
	}

	crypter := crypt.NewFromHash(secret)
	err := crypter.Verify(secret, []byte(password))
	return err == nil
}

// RequireAuth is an http.HandlerFunc for BasicAuth which initiates
// the authentication process (or requires reauthentication).
func (a *BasicAuth) RequireAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentType, a.Headers.V().UnauthContentType)
	w.Header().Set(a.Headers.V().Authenticate, `Basic realm="`+a.Realm+`"`)
	w.WriteHeader(a.Headers.V().UnauthCode)
	w.Write([]byte(a.Headers.V().UnauthResponse))
}

// Wrap returns an http.HandlerFunc, which wraps
// AuthenticatedHandlerFunc with this BasicAuth authenticator's
// authentication checks. Once the request contains valid credentials,
// it calls wrapped AuthenticatedHandlerFunc.
//
// Deprecated: new code should use NewContext instead.
func (a *BasicAuth) Wrap(wrapped AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
		} else {
			ar := &AuthenticatedRequest{Request: *r, Username: username}
			wrapped(w, ar)
		}
	}
}

// NewContext returns a context carrying authentication information for the request.
func (a *BasicAuth) NewContext(ctx context.Context, r *http.Request) context.Context {
	info := &Info{Username: a.CheckAuth(r), ResponseHeaders: make(http.Header)}
	info.Authenticated = (info.Username != "")
	if !info.Authenticated {
		info.ResponseHeaders.Set(a.Headers.V().Authenticate, `Basic realm="`+a.Realm+`"`)
	}
	return context.WithValue(ctx, infoKey, info)
}

// NewBasicAuthenticator returns a BasicAuth initialized with provided
// realm and secrets.
//
// Deprecated: new code should construct BasicAuth values directly.
func NewBasicAuthenticator(realm string, secrets SecretProvider) *BasicAuth {
	return &BasicAuth{Realm: realm, Secrets: secrets}
}
