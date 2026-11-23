"""Generate a random API token and its API_TOKENS entry.

Usage:
    uv run python scripts/make_token.py grok-viewer viewer
    uv run python scripts/make_token.py --hash-only
        (asks for the token without echoing it; or pipe it in:
         printf %s "$TOKEN" | uv run python scripts/make_token.py --hash-only)

The token to hash is never taken on the command line, where it would land in shell
history and be visible to other users in the process list.
"""

import argparse
import getpass
import hashlib
import secrets
import sys

ROLES = ("viewer", "editor", "admin")


def read_secret() -> str:
    """The token to hash: prompted for without echo on a terminal, else read from stdin."""
    if sys.stdin.isatty():
        return getpass.getpass("Token to hash: ")
    return sys.stdin.read().strip()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate an API token and its SHA-256 hash.")
    parser.add_argument("name", nargs="?", help="token name, e.g. grok-viewer")
    parser.add_argument("role", nargs="?", choices=ROLES)
    parser.add_argument(
        "--hash-only",
        action="store_true",
        help="only print the hash of a token read from stdin (prompted for without echo)",
    )
    args = parser.parse_args(argv)

    if args.hash_only:
        if args.name or args.role:
            parser.error("--hash-only reads the token from stdin, not the command line")
        token = read_secret()
        if not token:
            parser.error("no token given on stdin")
        print(hashlib.sha256(token.encode()).hexdigest())
        return
    if not args.name or not args.role:
        parser.print_help()
        sys.exit(2)

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(
        f"Token (give this to Grok; store it somewhere safe, it is shown only once):\n  {token}\n"
    )
    print(f"API_TOKENS entry (put this in Vercel):\n  {args.name}:{args.role}:{digest}")


if __name__ == "__main__":
    main()
