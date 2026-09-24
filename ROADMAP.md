# Roadmap

Themes, not dates. Nothing here is a commitment; the [issue tracker](https://github.com/kanywst/y509/issues) is the source of truth.

y509 answers two questions: *does this chain verify*, and *was it served correctly*. A check belongs here only if it predicts a client failure. It is not a general TLS scanner.

Current release: v1.4.0. Landscape last reviewed 2026-09-17.

## Why it exists

- **Missing intermediates.** Browsers fetch or cache them; curl, Go, Java, Python and Node do not. The same chain works in a browser and fails in a client.
- **Expiry outages.** Over a third of organisations had one in the past year (DigiCert, September 2026).
- **Rotation nobody picks up.** What is served can differ from what was issued, and cert-manager leaves that out of scope.
- **Existing tools miss it.** `openssl s_client` exits 0 when verification fails. SSL Labs cannot reach an internal host.
- **Lifetimes are shrinking.** 200 days today, 100 from 2027-03-15. Less slack for a missed renewal.
- **Inventory is a compliance requirement.** PCI DSS 4.0.1 since 2025-03-31, plus post-quantum migration.

## Next

- **Can a stapled OCSP response fail the build?** A revoked or stale one predicts a client failure, but adding it to `Findings` would trip every existing `fail-on: mis-served` gate. It needs its own JSON key and `ok`, the same problem conformance findings have.

## Keeping up with X.509

A valid certificate must render completely. A malformed one is a finding.

- **Revocation findings.** Stapled responses are already read. A missing OCSP pointer is never a finding; a missing AIA is; a missing CRL distribution point is only when the certificate is neither short-lived nor has an OCSP pointer. Any network check is CRL-only, opt-in and cached.
- **Conformance findings.** SHA-1, RSA under 2048 bits, CN without SAN, forbidden extensions. Needs its own key and `ok` (see Next). Decide between importing zlint and hand-rolling the few rules that matter.
- **Name unknown signature algorithms.** Go prints `0` for SLH-DSA. Read `RawSignatureAlgorithm` (Go 1.27) and extend `pqcAlgorithmNames` with SLH-DSA and composite ML-DSA.
- **Go 1.27 floor.** Brings ML-DSA natively and makes the ML-DSA rows in `pqcAlgorithmNames` dead code. The bump touches go.mod, README, CONTRIBUTING, the landing page and the FreeBSD port.
- **Large post-quantum certificates are normal.** An ML-DSA-87 signature is 4,627 bytes, SLH-DSA-256f 49,856. Private CAs issue them today.
- **Extensions view.** Nothing reads `cert.Extensions` yet. List OID, name and the critical bit, and flag the ones that are findings: CT poison in a served certificate, `acmeIdentifier` on a leaf, `nameConstraints` or `policyConstraints` on a leaf, Must-Staple, unhandled critical extensions.
- **Certificate Transparency, offline.** Count SCTs and name their logs from a bundled log list. Do not depend on a live log API.
- **International names.** Show punycode next to Unicode. Column width must use display width (`uniseg`), not rune count.
- **No-expiry sentinel.** Detect a `9999-12-31` `NotAfter` instead of showing a 2.9-million-day lifetime.
- **Watch.** Merkle Tree Certificates (experimental). TLS trust anchor identifiers (near approval) make serving different chains to different clients correct, so design for it now.

## Presentation rules

- **Two severities.** "Does not verify" blocks. "Verifies but fragile" advises. Different words, different colours.
- **Fixed vocabulary.** A short phrase ("missing issuer"), one clause of why, and the fix. Never a bare boolean or a colour alone.
- **Say which question was answered.** Which verifier, and whether it fetched anything to get there.
- **Label what cannot be decoded.** `unrecognized extension (OID 1.2.3.4, 47 bytes)`, never silence.
- **Promote what is actionable.** Footer hints, then the `?` overlay, then the docs.
- **Truncate with a marker**, never hide.
- **JSON is first-class.** Anything shown is reachable as JSON.
- **Changes land in several places.** The landing page, man page and completions copy the tabs, flags and constants.

## Later

- **Packaging.** winget (#138), AUR and nix (#139). Scoop already updates itself.
- **Malformed-certificate fixtures.** One shared helper instead of every package building its own.

## Non-goals

- **Not a TLS scanner.** Use `testssl.sh` or `sslyze` for ciphers and protocols.
- **No AIA chasing.** It would hide the exact misconfiguration y509 exists to find. Opt-in CRL checks are different: they add facts, they do not fill gaps.
- **No issuance.** No CA, no key generation, no CSRs.
- **Read-only.** Nothing mutates a remote.
- **No second certificate parser.** Read raw ASN.1 only far enough to label it, as `isPKCSContainer` does.
