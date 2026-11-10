"""Identities and header precedence.

For single-user testing you put the token in ProgramConfig.required_headers and
it's stamped on everything. For cross-account testing (IDOR/BOLA) you instead
define named identities — each a set of auth headers — and the agent sends a
request *as* a chosen identity. The whole point is to replay one user's request
as another user and see whether authorization actually stops it.

Precedence, lowest to highest:
  request headers  <  identity (auth)  <  required_headers (compliance)

So the program's required headers (e.g. a bug-bounty identifier) can never be
dropped by a mutation or an identity, while the identity supplies the auth.
Therefore, for multi-identity testing, keep auth OUT of required_headers (or it
would override every identity) and put it in the identities instead.
"""
from __future__ import annotations


def resolve_identity(identities: dict, name: str | None, default: str | None) -> dict:
    chosen = name if name is not None else default
    if chosen is None:
        return {}
    if chosen not in identities:
        raise ValueError(f"unknown identity {chosen!r}; known: {sorted(identities)}")
    return dict(identities[chosen])


def merge_headers(req_headers: dict | None, identity_headers: dict | None,
                  required_headers: dict | None) -> dict:
    merged = dict(req_headers or {})
    merged.update(identity_headers or {})
    merged.update(required_headers or {})
    return merged
