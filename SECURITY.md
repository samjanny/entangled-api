# Security policy

The `entangled-api` workspace implements cryptographic and parsing
primitives that are load-bearing for the Entangled v1.0 protocol's
publisher-trust model. Issues affecting signature verification,
canonicalization, parsing, state handling, or origin binding are
treated as security vulnerabilities.

## Reporting a vulnerability

Please report security issues **privately** through one of the
following channels — **do not file a public GitHub issue or
discussion**:

1. **GitHub private vulnerability reporting** (preferred): open a
   private advisory at
   <https://github.com/samjanny/entangled-api/security/advisories/new>.
2. **Email fallback**: `samjanny@gmail.com` with a subject line
   starting `[entangled-api security]`. Encrypting with GPG is
   welcome but not required.

Include in the report:

- the affected crate (`entangled-core`) and version or commit SHA;
- a minimal reproducer if available (a single failing test or a
  byte-level payload is ideal);
- the area touched (signature verification, canonicalization,
  parsing, canary state, origin binding, API misuse);
- any known constraints on exploitability (e.g. requires a malicious
  publisher vs. requires a network-position attacker).

If the issue is sensitive enough that even the title is risky to
share, write to the email fallback first and we will set up a
private channel.

## Response timeline

The maintainers aim to:

- **acknowledge** a report within **3 business days**;
- provide an **initial assessment** (severity, accepted scope, likely
  remediation window) within **7 business days**;
- coordinate a **fix and disclosure schedule** before any public
  discussion of the issue.

We may ask for additional information, propose a coordinated
disclosure date, or — for issues that do not affect the published
crate versions — close the report as out of scope with a written
explanation.

## Disclosure norms

We follow coordinated disclosure:

- Reporters and maintainers agree on an embargo window that allows a
  patched release to ship and a reasonable upgrade period for
  downstream consumers.
- We default to a **90-day** embargo from initial acknowledgement.
  Sooner disclosure is fine for issues that are already publicly
  discoverable; longer embargoes may be needed for issues that
  require a coordinated spec revision in the upstream
  [`samjanny/entangled`](https://github.com/samjanny/entangled)
  repository.
- Credit in the published advisory follows the reporter's preference
  (named, pseudonymous, or anonymous).

## Scope

In scope:

- the `entangled-core` crate published from this workspace;
- the build, test, and supply-chain configuration (`Cargo.toml`,
  `Cargo.lock`, `deny.toml`, GitHub Actions workflows) that affects
  what ships to crates.io;
- documented public APIs and their interaction with the upstream
  spec.

Out of scope:

- the upstream protocol specification at
  [`samjanny/entangled`](https://github.com/samjanny/entangled) —
  report spec-level issues there;
- third-party transports, clients, or applications that integrate
  this crate;
- vulnerabilities in transitive dependencies that are already
  publicly disclosed and tracked by `cargo audit` (please update or
  pin them in your own dependency tree).

## Hardening practices

Defensive measures already in place:

- `#![forbid(unsafe_code)]` at the `entangled-core` crate root;
- daily `cargo audit` in CI (`.github/workflows/audit.yml`);
- `cargo deny` for license, supply-chain, and registry-allowlist
  policy (`deny.toml`, `.github/workflows/deny.yml`);
- a conformance corpus pinned in lockstep with the crate's
  `SPEC_REVISION` constant (a corpus that drifts ahead of or behind
  the code fails CI loudly);
- a `must_use` type-state chain on manifest verification so that
  Stage 8 (canary) and Stage 9 (origin binding) cannot be silently
  skipped.

When you find a gap in this list, please tell us.
