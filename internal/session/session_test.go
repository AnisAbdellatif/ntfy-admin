package session

import (
	"sync"
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	var mu sync.Mutex
	var revoked []string
	st := NewStore(func(s *Session) {
		mu.Lock()
		revoked = append(revoked, s.Token)
		mu.Unlock()
	})
	now := time.Now()
	st.now = func() time.Time { return now }

	a := st.Create("admin", "tk_a", now.Add(time.Hour))
	b := st.Create("admin", "tk_b", now.Add(2*time.Hour))
	if a.ID == b.ID || a.CSRF == b.CSRF || len(a.ID) < 40 {
		t.Fatal("session IDs / CSRF tokens must be random and distinct")
	}
	if st.Get(a.ID) != a {
		t.Fatal("expected session a")
	}
	if st.Get("nope") != nil || st.Get("") != nil {
		t.Fatal("unknown session must be nil")
	}

	now = now.Add(90 * time.Minute)
	if st.Get(a.ID) != nil {
		t.Fatal("expired session must be nil")
	}
	// Revocation of an expired session runs in the background.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(revoked) == 1 && revoked[0] == "tk_a"
	})

	st.Delete(b.ID)
	st.Delete(b.ID) // no double revoke
	mu.Lock()
	defer mu.Unlock()
	if len(revoked) != 2 || revoked[1] != "tk_b" {
		t.Fatalf("deleted session token must be revoked once, got %v", revoked)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSweepAndShutdown(t *testing.T) {
	var mu sync.Mutex
	n := 0
	st := NewStore(func(*Session) { mu.Lock(); n++; mu.Unlock() })
	now := time.Now()
	st.now = func() time.Time { return now }
	st.Create("a", "tk_1", now.Add(time.Minute))
	st.Create("a", "tk_2", now.Add(time.Hour))
	now = now.Add(2 * time.Minute)
	st.Sweep()
	if n != 1 || st.Len() != 1 {
		t.Fatalf("sweep: revoked=%d len=%d", n, st.Len())
	}
	st.Shutdown()
	if n != 2 || st.Len() != 0 {
		t.Fatalf("shutdown: revoked=%d len=%d", n, st.Len())
	}
}

func TestSessionState(t *testing.T) {
	s := &Session{CSRF: "secret"}
	if !s.ValidCSRF("secret") || s.ValidCSRF("") || s.ValidCSRF("other") {
		t.Fatal("csrf comparison broken")
	}
	s.AddFlash("ok", "one")
	s.AddFlash("error", "two")
	if f := s.PopFlashes(); len(f) != 2 || f[1].Message != "two" {
		t.Fatalf("flashes: %v", f)
	}
	if f := s.PopFlashes(); len(f) != 0 {
		t.Fatal("flashes must be one-shot")
	}
	id := s.AddReveal(&Reveal{Account: "svc-a", Token: "tk_x"})
	id2 := s.AddReveal(&Reveal{Account: "svc-a", Token: "tk_y"})
	if s.PopReveal(id, "svc-b") != nil {
		t.Fatal("reveal must be bound to its account")
	}
	if r := s.PopReveal(id, "svc-a"); r == nil || r.Token != "tk_x" {
		t.Fatal("expected first reveal")
	}
	if s.PopReveal(id, "svc-a") != nil {
		t.Fatal("reveal must be one-shot")
	}
	if r := s.PopReveal(id2, "svc-a"); r == nil || r.Token != "tk_y" {
		t.Fatal("concurrent reveals must not overwrite each other")
	}
	for range maxReveals + 5 {
		s.AddReveal(&Reveal{Account: "svc-a"})
	}
	if len(s.reveals) != maxReveals {
		t.Fatalf("unshown reveals must be capped, have %d", len(s.reveals))
	}
	s.SetTokenRefs("svc-a", []string{"tk_1", "tk_2"})
	if tok, ok := s.TokenRef("svc-a", 1); !ok || tok != "tk_2" {
		t.Fatal("token ref lookup broken")
	}
	if _, ok := s.TokenRef("svc-a", 2); ok {
		t.Fatal("out of range index must fail")
	}
	if _, ok := s.TokenRef("svc-b", 0); ok {
		t.Fatal("refs must be per account")
	}
}
