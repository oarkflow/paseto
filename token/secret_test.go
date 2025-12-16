package token

import (
	"testing"
)

// Ensure generated strings do not point to pooled buffers that may be reused
// This prevents subtle corruption where a returned string could change later
// because it referenced mutable pooled memory.
func TestStringImmutability(t *testing.T) {
	g := NewSecretGenerator()

	s, err := g.String(32)
	if err != nil {
		t.Fatalf("initial String failed: %v", err)
	}

	// snapshot the bytes to detect later mutation
	snap := append([]byte(nil), s...)

	// force pool reuse
	for i := 0; i < 200; i++ {
		if _, err := g.String(32); err != nil {
			t.Fatalf("String call %d failed: %v", i, err)
		}
	}

	// original should still match snapshot
	if string(snap) != s {
		t.Fatalf("generated string mutated: got %q, want %q", s, string(snap))
	}
}

func TestStringWithPrefixImmutability(t *testing.T) {
	g := NewSecretGenerator().WithPrefix("pfx-")

	s, err := g.String(16)
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	snap := append([]byte(nil), s...)

	for i := 0; i < 200; i++ {
		if _, err := g.String(16); err != nil {
			t.Fatalf("String call %d failed: %v", i, err)
		}
	}

	if string(snap) != s {
		t.Fatalf("generated string with prefix mutated: got %q, want %q", s, string(snap))
	}
}
