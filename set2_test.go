package cryptopals

import "testing"

func TestPKCSPadding(t *testing.T) {
	if l := len(PKCSPadding([]byte("YELLOW SUBMARINE"), 20)); l != 20 {
		t.Fatalf("length must be 20, but got %d", l)
	}
}
