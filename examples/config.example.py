"""Example program config — fill in with scope you have VERIFIED yourself.

Copy this, replace the placeholders with the hosts/headers from the program's
official policy (not a pasted summary), and keep the rate at or under the stated
ceiling. The hosts below are deliberately fake.
"""
from probe import ProgramConfig

config = ProgramConfig(
    name="example-program",
    allowed_hosts=[
        "api.example-staging.test",
        "dashboard.example-staging.test",
    ],
    required_headers={
        # Many programs require a researcher-identifier header on every request.
        "X-Bug-Bounty": "HackerOne-<your-username>",
    },
    max_requests_per_sec=5.0,   # keep under the program's stated limit
    jitter_seconds=0.05,
    follow_redirects=False,     # in-scope pages may link to production
)
