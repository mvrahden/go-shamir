# go-shamir

[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
over GF(256) — a Go **library** and a small CLI.

The implementation is HashiCorp Vault's, vendored rather than imported (see
[Provenance](#provenance)). It splits an arbitrarily long secret into `n`
shares of which any `k` reconstruct it, and `k-1` reveal nothing.

## Library

```go
import shamir "github.com/mvrahden/go-shamir"

shares, err := shamir.Split(secret, 5, 3)   // 5 shares, any 3 reconstruct
secret, err := shamir.Combine(shares[:3])
```

The package has **no dependencies outside the standard library**. (`cobra`
appears in `go.mod` for the CLI in `cmd/`, and is not built when you import
the library.)

Each share is `len(secret)+1` bytes: the secret's length, plus a trailing
byte holding its x-coordinate.

### ⚠ Combine does not know the threshold — verify your plaintext

Nothing in a share records `k`. `Combine` interpolates whatever it is handed
and returns a result, so **given too few shares it returns wrong bytes and a
nil error**. It cannot detect this, and neither can you from the error alone.
`TestBelowThresholdReturnsGarbageWithoutError` measures it: for a 3-of-5
split, all 10 two-share subsets return garbage without complaint.

So a caller must be able to recognise a correct plaintext. Give the secret a
canonical structure and check it after reconstructing:

```go
const header = "my-secret-v1\n"

plain, err := shamir.Combine(shares)
if err != nil || !bytes.HasPrefix(plain, []byte(header)) {
    return errors.New("not enough shares, or a share is corrupt")
}
```

Random bytes will not begin with your header, so a wrong reconstruction is
caught with negligible false-accept probability. This costs nothing and turns
a silent wrong answer into an error.

There is also no per-share integrity check. If shares are transcribed by hand
or stored for years, wrap each one in a checksum of your own so a single bad
share can be identified **without** gathering the rest of them.

## CLI

Split a secret:

```sh
$ echo -n "very very secret" | ./bin/shamir split -p 4 -t 2
baa3e1b656d6b253052d293b99daf7fa4a
07cfbaa1bf6982413dd52abb2578ca6373
c9cc6036850debccca9dd598bebf27acd1
db7b57989fb3d27775c62f20fa858dd338
```

Combine it again:

```sh
$ cat <<EOF | ./bin/shamir combine
> 07cfbaa1bf6982413dd52abb2578ca6373
> c9cc6036850debccca9dd598bebf27acd1
> EOF
very very secret
```

## What the tests guarantee

`shamir_test.go` is upstream's suite. `shamir_property_test.go` adds
exhaustive checks against the ways this construction fails *silently*:

- **No share ever carries x = 0.** The secret is the polynomial at zero, so a
  share issued at x = 0 is the plaintext itself. This is the classic
  from-scratch catastrophe and it hides perfectly — everything still
  round-trips. Verified over 11,440 shares across every `(k,n)` from 2 to 12.
- **Every `k`-subset reconstructs**, checked exhaustively rather than
  sampled, because interpolation bugs can work for some subsets and not
  others.
- **Below-threshold reconstruction never yields the secret** or anything
  passing a header check.
- Arbitrary-length secrets round-trip, and share length is always
  `len(secret)+1`.
- Two splits of one secret differ, so the coefficients are not fixed.
- Out-of-range parameters are refused.

## Security notes

Coefficients come from `crypto/rand`. `math/rand` is used only to permute the
**public** x-coordinates, which are not secret.

The arithmetic is **not constant-time**, and a
[timing side channel](http://sbudella.altervista.org/blog/20230330-shamir-timing.html)
has been described in this implementation. Exploiting it needs an adversary
measuring the machine while it splits or combines. That is acceptable for
one-shot use on an air-gapped host, and not obviously acceptable for a
network service doing it repeatedly. Decide which you are.

## Provenance

`shamir.go` and `shamir_test.go` are vendored from
[`hashicorp/vault/shamir`](https://github.com/hashicorp/vault/tree/v1.17.3/shamir)
at **v1.17.3**, unmodified apart from a provenance header. They remain under
the **Mozilla Public License 2.0**; `LICENSE` is HashiCorp's own licence file
from that same directory.

MPL-2.0 is file-level copyleft: those files stay MPL, and the rest of this
module does not become MPL by including them.

They are vendored rather than imported because reaching one stdlib-only file
through the module graph would mean depending on the whole
`github.com/hashicorp/vault` module — whose top-level LICENSE is BUSL-1.1
(the `shamir` subdirectory carries its own MPL-2.0 licence, which is why the
code is usable at all) and whose dependency graph is enormous.
