# Security policy

Bot RBAC holds Google Drive tokens, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/parthit/botrbac/security/advisories/new>).

Include what an attacker could reach (for example, a file outside the allowlist, another person's data, or a
token), steps to reproduce, and the version or commit. You should get a reply within a few days.

## Scope

In scope: this code and the hosted instance at botrbac.com. Examples: reading or changing a Drive item
that is not allowlisted, acting as another user, leaking tokens or `ENCRYPTION_KEY`-protected data, bypassing
a connected app's role, or the mailbox reaching another person's assistant.

Out of scope: an assistant following instructions written inside a document you allowed (prompt injection
within the allowlist is a known limit, see [docs/security.md](docs/security.md)), rate-limit tuning, and
reports from automated scanners without a working impact.

How the allowlist check works: [docs/security.md](docs/security.md).
