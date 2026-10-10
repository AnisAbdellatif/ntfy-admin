// Package session keeps ntfy-admin's server-side sessions in memory. A session
// holds the ntfy admin's bearer token; the token never reaches the browser.
package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// Flash is a one-shot message shown after a redirect.
type Flash struct {
	Kind    string // "ok" or "error"
	Message string
}

// Reveal is a freshly issued token, shown exactly once.
type Reveal struct {
	Account string
	Token   string
	Label   string
	Expires int64
}

// Session is one logged-in ntfy admin.
type Session struct {
	ID       string
	Username string
	Token    string // ntfy bearer token (tk_…), server-side only
	CSRF     string
	Expires  time.Time

	mu          sync.Mutex
	flashes     []Flash
	reveals     map[string]*Reveal // reveal ID -> token, until shown
	revealOrder []string
	tokenRefs   map[string][]string // service account -> token values, in the order last shown
}

// AddFlash queues a flash message.
func (s *Session) AddFlash(kind, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flashes = append(s.flashes, Flash{Kind: kind, Message: msg})
}

// PopFlashes returns and clears queued flash messages.
func (s *Session) PopFlashes() []Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flashes
	s.flashes = nil
	return f
}

// maxReveals bounds unshown tokens per session; the oldest are dropped.
const maxReveals = 10

// AddReveal stores a token to show once and returns its reveal ID, which the
// redirect carries to the page that shows it. IDs keep concurrent tabs from
// showing (and losing) each other's tokens.
func (s *Session) AddReveal(r *Reveal) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reveals == nil {
		s.reveals = map[string]*Reveal{}
	}
	id := RandomString(12)
	s.reveals[id] = r
	s.revealOrder = append(s.revealOrder, id)
	for len(s.revealOrder) > maxReveals {
		delete(s.reveals, s.revealOrder[0])
		s.revealOrder = s.revealOrder[1:]
	}
	return id
}

// PopReveal returns and forgets the token with the given reveal ID, if it
// belongs to account.
func (s *Session) PopReveal(id, account string) *Reveal {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reveals[id]
	if r == nil || r.Account != account {
		return nil
	}
	delete(s.reveals, id)
	return r
}

// SetTokenRefs remembers the token values of a service account in display
// order, so that forms can reference tokens by index instead of value.
func (s *Session) SetTokenRefs(account string, tokens []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenRefs == nil {
		s.tokenRefs = map[string][]string{}
	}
	s.tokenRefs[account] = tokens
}

// TokenRef resolves an index from the last displayed token list.
func (s *Session) TokenRef(account string, idx int) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.tokenRefs[account]
	if idx < 0 || idx >= len(refs) {
		return "", false
	}
	return refs[idx], true
}

// ValidCSRF compares a submitted CSRF token in constant time.
func (s *Session) ValidCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRF)) == 1
}

// RevokeFunc is called when a session ends, to revoke its ntfy token.
type RevokeFunc func(s *Session)

// Store is an in-memory session store.
type Store struct {
	revoke RevokeFunc
	now    func() time.Time

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewStore creates a store. revoke may be nil.
func NewStore(revoke RevokeFunc) *Store {
	return &Store{revoke: revoke, now: time.Now, sessions: map[string]*Session{}}
}

// RandomString returns n random bytes, base64url-encoded.
func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create starts a session for an ntfy admin with the given bearer token.
func (st *Store) Create(username, token string, expires time.Time) *Session {
	s := &Session{
		ID:       RandomString(32),
		Username: username,
		Token:    token,
		CSRF:     RandomString(32),
		Expires:  expires,
	}
	st.mu.Lock()
	st.sessions[s.ID] = s
	st.mu.Unlock()
	return s
}

// Get returns a live session, or nil. Expired sessions are ended; their
// tokens are revoked in the background so the request is not held up.
func (st *Store) Get(id string) *Session {
	if id == "" {
		return nil
	}
	st.mu.Lock()
	s, ok := st.sessions[id]
	if ok && !st.now().Before(s.Expires) {
		delete(st.sessions, id)
		st.mu.Unlock()
		go st.end(s)
		return nil
	}
	st.mu.Unlock()
	return s
}

// Delete ends a session and revokes its token. It is a no-op for unknown IDs.
func (st *Store) Delete(id string) {
	st.mu.Lock()
	s, ok := st.sessions[id]
	delete(st.sessions, id)
	st.mu.Unlock()
	if ok {
		st.end(s)
	}
}

// Len returns the number of stored sessions.
func (st *Store) Len() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.sessions)
}

func (st *Store) end(s *Session) {
	if st.revoke != nil {
		st.revoke(s)
	}
}

// Sweep ends all expired sessions.
func (st *Store) Sweep() {
	now := st.now()
	var expired []*Session
	st.mu.Lock()
	for id, s := range st.sessions {
		if !now.Before(s.Expires) {
			expired = append(expired, s)
			delete(st.sessions, id)
		}
	}
	st.mu.Unlock()
	for _, s := range expired {
		st.end(s)
	}
}

// Shutdown ends all sessions (used on graceful shutdown, so that no session
// tokens are left behind in ntfy). Tokens are revoked concurrently; it
// returns when all revocations have finished.
func (st *Store) Shutdown() {
	st.mu.Lock()
	all := st.sessions
	st.sessions = map[string]*Session{}
	st.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.end(s)
		}()
	}
	wg.Wait()
}
