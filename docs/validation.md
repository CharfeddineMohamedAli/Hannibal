# Validating Hannibal against a local lab

Everything in this repo is tested offline with fakes — the wiring is correct, but
that doesn't prove it finds *real* bugs or avoids false positives. This runbook
walks a first real run against an intentionally-vulnerable app **you host**.

> Only ever run this against a target you own or are explicitly authorised to
> test. A local lab on your own machine is the safe way to validate.

## 1. Stand up a lab

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) in Docker:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
# now reachable at http://localhost:3000
```

(DVWA or your own staging app work too — just adjust the host.)

## 2. Point the tool at it

Use `examples/juice-shop.config.json`. Note `allowed_hosts` is the **hostname**
(`localhost`) — the scope guard matches on host, so any port on it is in scope,
which is what you want for a lab. Set your key and run:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m probe run \
  --config examples/juice-shop.config.json \
  --goal "Test the product search and the /rest/products endpoints for injection and reflection." \
  --seed "http://localhost:3000/rest/products/search?q=apple" \
  --report juice-shop-findings.md
```

## 3. Read the result critically

Open `juice-shop-findings.md` and ask the two questions that matter:

- **Did it find the real bugs?** Juice Shop has known SQLi in the product search,
  among others. Did the agent surface them, with evidence and reproduction?
- **Did it avoid crying wolf?** Look for anything reported where the input is
  actually encoded/validated. A good run reports few, solid findings — the
  reachable-vs-gated discipline should suppress the noise. False positives here
  are the most useful thing you can learn: they tell you exactly where the oracle
  or the agent's judgment needs work.

## 4. Iterate from evidence

Whatever the run exposes is the real next priority — missing surface discovery
(you had to hand it seeds), weak detection on a bug class, or a false positive
pattern. Fix that, re-run, compare. That loop — not more features in the dark —
is how the tool gets good.

## Multi-account (IDOR) validation

Register two Juice Shop accounts, grab each token, and add them as identities in
the config:

```json
"identities": {
  "A": {"Authorization": "Bearer <token-A>"},
  "B": {"Authorization": "Bearer <token-B>"}
},
"default_identity": "A"
```

Then goal it at an object that belongs to A (e.g. a basket or order id) and ask
it to check cross-account access. A correct run replays A's request as B and only
reports if B actually receives A's object.
