package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/samma-io/mcp/internal/sammaapi"
)

const (
	extraToken = "samma.token"
	extraMe    = "samma.me"
)

// Verifier validates bearer tokens against the app's GET /api/v1/me and
// caches positive results briefly, keyed by SHA-256 of the token.
type Verifier struct {
	api *sammaapi.Client
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	me      *sammaapi.Me
	expires time.Time
}

func NewVerifier(api *sammaapi.Client, ttl time.Duration) *Verifier {
	return &Verifier{api: api, ttl: ttl, now: time.Now, cache: map[string]cached{}}
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// Verify implements auth.TokenVerifier.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	key := hashToken(token)
	now := v.now()

	v.mu.Lock()
	c, ok := v.cache[key]
	if ok && now.After(c.expires) {
		delete(v.cache, key)
		ok = false
	}
	v.mu.Unlock()

	if !ok {
		me, err := v.api.Me(ctx, token)
		if err != nil {
			if sammaapi.IsStatus(err, http.StatusUnauthorized) || sammaapi.IsStatus(err, http.StatusForbidden) {
				return nil, auth.ErrInvalidToken
			}
			return nil, fmt.Errorf("verify token: %w", err)
		}
		c = cached{me: me, expires: now.Add(v.ttl)}
		v.mu.Lock()
		if len(v.cache) > 10000 { // crude bound; entries are tiny and short-lived
			v.cache = map[string]cached{}
		}
		v.cache[key] = c
		v.mu.Unlock()
	}

	return &auth.TokenInfo{
		UserID:     c.me.Organisation.ID + ":" + key[:16],
		Expiration: c.expires,
		Extra:      map[string]any{extraToken: token, extraMe: c.me},
	}, nil
}

// callerFrom extracts the caller's raw token and identity from a tool request.
func callerFrom(ti *auth.TokenInfo) (string, *sammaapi.Me, error) {
	if ti == nil {
		return "", nil, fmt.Errorf("unauthenticated")
	}
	tok, _ := ti.Extra[extraToken].(string)
	me, _ := ti.Extra[extraMe].(*sammaapi.Me)
	if tok == "" || me == nil {
		return "", nil, fmt.Errorf("unauthenticated")
	}
	return tok, me, nil
}
