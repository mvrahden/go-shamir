// Property tests for the vendored implementation.
//
// These are not upstream's; shamir_test.go carries those. These guard the
// specific ways a Shamir implementation fails CATASTROPHICALLY AND SILENTLY,
// which is the only interesting failure mode for code that stands between
// someone and their money.
//
// Unlike shamir_test.go these are exhaustive rather than illustrative: every
// k-subset is checked, not one.

package shamir

import (
	"bytes"
	"strings"
	"testing"
)

// combinations returns every k-sized subset of indices [0,n).
func combinations(n, k int) [][]int {
	var out [][]int
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
			out = append(out, append([]int(nil), idx...))
			return
		}
		for i := start; i < n; i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
	return out
}

func subset(shares [][]byte, idx []int) [][]byte {
	out := make([][]byte, 0, len(idx))
	for _, i := range idx {
		out = append(out, shares[i])
	}
	return out
}

// TestNoShareCarriesXZero is the single most important test in this package.
//
// A share is the polynomial evaluated at its x-coordinate, and the secret is
// the polynomial evaluated at ZERO. So a share issued with x = 0 is not a
// share at all — it is the plaintext secret, handed out in the clear.
//
// This is the classic catastrophic bug in from-scratch Shamir, and it hides
// perfectly: every reconstruction still round-trips, every test still passes,
// and one shareholder silently holds everything.
func TestNoShareCarriesXZero(t *testing.T) {
	secret := []byte("the quick brown fox jumps over the lazy dog")
	checked := 0
	for n := 2; n <= 12; n++ {
		for k := 2; k <= n; k++ {
			for trial := 0; trial < 20; trial++ {
				shares, err := Split(secret, n, k)
				if err != nil {
					t.Fatalf("Split(%d-of-%d): %v", k, n, err)
				}
				for i, s := range shares {
					checked++
					if x := s[len(s)-1]; x == 0 {
						t.Fatalf("share %d of a %d-of-%d split carries x=0 — it IS the secret", i, k, n)
					}
				}
			}
		}
	}
	t.Logf("%d shares checked, none at x=0", checked)
}

// TestEveryKSubsetReconstructs checks the threshold exhaustively rather than
// sampling one subset, because an off-by-one in the interpolation can work
// for some subsets and not others.
func TestEveryKSubsetReconstructs(t *testing.T) {
	secret := []byte("vault-sheets-v1\nA: sheet a words\nB: sheet b words\n")
	for _, kn := range [][2]int{{2, 3}, {3, 5}, {2, 4}, {3, 4}, {4, 5}, {5, 5}, {2, 8}, {6, 8}} {
		k, n := kn[0], kn[1]
		shares, err := Split(secret, n, k)
		if err != nil {
			t.Fatalf("Split(%d-of-%d): %v", k, n, err)
		}
		for _, c := range combinations(n, k) {
			got, err := Combine(subset(shares, c))
			if err != nil {
				t.Fatalf("%d-of-%d subset %v: %v", k, n, c, err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("%d-of-%d subset %v reconstructed the wrong secret", k, n, c)
			}
		}
	}
}

// TestBelowThresholdReturnsGarbageWithoutError documents the behaviour that
// makes a self-verifying plaintext MANDATORY for any caller.
//
// Combine does not know the threshold — nothing in the shares tells it — so
// it interpolates whatever it is handed and returns a result. Given k-1
// shares it returns WRONG BYTES AND A NIL ERROR. A caller that trusts the
// error alone will hand a wrong "secret" onward and never know.
//
// The kit's answer is a canonical header on the plaintext: reconstruct, then
// refuse anything that does not start with it. This test pins the premise.
func TestBelowThresholdReturnsGarbageWithoutError(t *testing.T) {
	const header = "vault-sheets-v1\n"
	secret := []byte(header + "A: sheet a\nB: sheet b\n")

	k, n := 3, 5
	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}

	silent := 0
	for _, c := range combinations(n, k-1) {
		got, err := Combine(subset(shares, c))
		if err == nil {
			silent++
			if bytes.Equal(got, secret) {
				t.Fatalf("subset %v of a %d-of-%d split RECOVERED THE SECRET below threshold", c, k, n)
			}
			if strings.HasPrefix(string(got), header) {
				t.Fatalf("subset %v produced output passing the header check below threshold", c)
			}
		}
	}
	if silent == 0 {
		t.Skip("Combine rejected every below-threshold subset; the header check is belt-and-braces here")
	}
	t.Logf("%d of %d below-threshold subsets returned wrong bytes with a nil error — "+
		"callers MUST verify the reconstructed plaintext, not just the error",
		silent, len(combinations(n, k-1)))
}

// TestArbitraryLengthRoundTrip: the secret is a text document of whatever
// length the operator's passphrases happen to make it, not a fixed-size key.
func TestArbitraryLengthRoundTrip(t *testing.T) {
	for _, size := range []int{1, 2, 16, 31, 64, 128, 129, 256, 1024} {
		secret := bytes.Repeat([]byte("abcdefgh"), (size/8)+1)[:size]
		shares, err := Split(secret, 5, 3)
		if err != nil {
			t.Fatalf("Split of %d bytes: %v", size, err)
		}
		if want := size + 1; len(shares[0]) != want {
			t.Fatalf("%d-byte secret produced a %d-byte share, want %d", size, len(shares[0]), want)
		}
		got, err := Combine(shares[:3])
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("%d-byte secret did not round-trip", size)
		}
	}
}

// TestSplitsAreNotDeterministic guards the randomness. Fresh coefficients
// must come from a CSPRNG on every call; identical shares across two splits
// of the same secret would mean the coefficients were fixed, and a fixed
// polynomial leaks the secret to anyone holding one share from each split.
func TestSplitsAreNotDeterministic(t *testing.T) {
	secret := []byte("the same secret, twice")
	a, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	identical := 0
	for i := range a {
		if bytes.Equal(a[i], b[i]) {
			identical++
		}
	}
	if identical == len(a) {
		t.Fatal("two splits of the same secret produced identical shares — coefficients are not random")
	}
}

// TestPolynomialNotReusedAcrossBytes guards the property that makes a
// KNOWN-PLAINTEXT secret safe to split.
//
// Each byte of the secret must get its own polynomial with its own random
// coefficients. If one polynomial were hoisted out of the loop and reused,
// identical plaintext bytes would produce identical share bytes — and then
// any caller whose plaintext has a predictable prefix (a format header, a
// magic number, a fixed field) would leak it into the rest of the secret.
//
// Nothing else in this suite would notice: reconstruction still round-trips
// perfectly with a reused polynomial. Hence this test.
func TestPolynomialNotReusedAcrossBytes(t *testing.T) {
	secret := bytes.Repeat([]byte{'A'}, 64)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, share := range shares {
		body := share[:len(share)-1] // drop the trailing x-coordinate
		distinct := map[byte]bool{}
		for _, b := range body {
			distinct[b] = true
		}
		if len(distinct) == 1 {
			t.Fatalf("share %d: %d identical plaintext bytes produced a constant share body — "+
				"the polynomial is reused across byte positions, so a known plaintext prefix would leak",
				i, len(secret))
		}
	}
}

// TestRejectsOutOfRangeParameters: the guards that keep callers out of
// undefined territory.
func TestRejectsOutOfRangeParameters(t *testing.T) {
	secret := []byte("secret")
	cases := []struct {
		name             string
		parts, threshold int
	}{
		{"threshold above parts", 3, 4},
		{"threshold below two", 5, 1},
		{"parts below two", 1, 1},
		{"parts above 255", 256, 3},
	}
	for _, c := range cases {
		if _, err := Split(secret, c.parts, c.threshold); err == nil {
			t.Errorf("Split(parts=%d, threshold=%d) was accepted (%s)", c.parts, c.threshold, c.name)
		}
	}
	if _, err := Split(nil, 5, 3); err == nil {
		t.Error("Split of an empty secret was accepted")
	}
}
