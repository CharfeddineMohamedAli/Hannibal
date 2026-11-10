"""Mutation layer.

Discovers injection points in a request (query parameters, flat JSON body
fields) and produces one mutated Request per (point, payload). Each mutation
carries a unique canary marker so the oracle can find *our* input in a response.

v1 covers query params and top-level JSON fields — the common API surface. Form
bodies and nested JSON are deliberate TODOs, noted so the gap is visible rather
than silently missed.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import Request
from .payloads import Payload, payloads_for


@dataclass
class Mutation:
    request: Request
    payload: Payload
    point: str      # e.g. "query:id" or "json:user_id"
    marker: str     # the canary actually embedded in this request


def _new_marker() -> str:
    # Lowercase alnum, unlikely to collide with page text or to be mangled.
    return "zq" + secrets.token_hex(4)


def discover_points(req: Request) -> list[str]:
    """Names the injectable points in a request, as 'query:<k>' / 'json:<k>'."""
    points: list[str] = []
    query = parse_qsl(urlsplit(req.url).query, keep_blank_values=True)
    points += [f"query:{k}" for k, _ in query]

    if req.body and "json" in req.headers.get("content-type", "").lower():
        try:
            data = json.loads(req.body.decode("utf-8", errors="strict"))
            if isinstance(data, dict):
                points += [f"json:{k}" for k in data.keys()]
        except (ValueError, UnicodeDecodeError):
            pass
    return points


def _apply_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs = [(k, value if k == key else v) for k, v in pairs]
    return urlunsplit(parts._replace(query=urlencode(pairs)))


def _apply_json(body: bytes, key: str, value: str) -> bytes:
    data = json.loads(body.decode("utf-8"))
    data[key] = value
    return json.dumps(data).encode("utf-8")


def mutate(
    req: Request,
    classes: list[str] | None = None,
    payloads: list[Payload] | None = None,
) -> list[Mutation]:
    """Every (injection point x payload) as a ready-to-send Mutation.

    By default uses the built-in catalogue. Pass `payloads` (e.g. from
    load_payload_file) to use your own set instead; if `classes` is also given,
    the set is filtered to those classes.
    """
    points = discover_points(req)
    out: list[Mutation] = []

    if payloads is None:
        source = payloads_for(classes)
    elif classes:
        keep = set(classes)
        source = [p for p in payloads if p.payload_class in keep]
    else:
        source = list(payloads)

    for point in points:
        kind, _, key = point.partition(":")
        for payload in source:
            marker = _new_marker()
            # replace() not format(): payloads are written literally, so braces
            # in e.g. {{7*7}} need no escaping and {m} is the only token.
            value = payload.template.replace("{m}", marker)
            if kind == "query":
                mutated = req.clone(
                    url=_apply_query(req.url, key, value),
                    note=f"{payload.payload_class} @ {point}",
                )
            elif kind == "json" and req.body is not None:
                mutated = req.clone(
                    body=_apply_json(req.body, key, value),
                    note=f"{payload.payload_class} @ {point}",
                )
            else:
                continue
            out.append(Mutation(request=mutated, payload=payload, point=point, marker=marker))
    return out
