# ADR 0007: Username and password sign-in for the analyst UI

Date: 2026-10-10 · Status: accepted · Changes the UI sign-in from the Phase 1 UI work

## Context
The analyst UI asked people to paste an API key to sign in. The owner found this confusing: keys
are long, shown once, and the same names collide with keys made for programs ("an API key named
'chandureddy' already exists"). They asked for a normal username and password on the sign-in
page instead.

## Decisions
1. **People sign in with a username and password; programs keep API keys.** The `/ui/login` form
   takes a username and password. API keys no longer open a UI session. They stay the only
   credential for `/api/v1/*`, which ReconX uses (ADR 0006), so the ReconX link is unchanged.
2. **Accounts live in a `users` table** (migration 0006). Each has a display name, a case-folded
   login (so "Chandu Reddy" and "chandu reddy" are the same account), a role (viewer/analyst/admin,
   the same RBAC as keys), and `disabled_at`.
3. **Passwords are hashed with scrypt** from the Python standard library (N=2^14, r=8, p=1,
   16-byte salt). That's a memory-hard password hash, so no new dependency is needed. Checks run
   in a worker thread. An unknown username costs the same hash computation as a wrong password,
   and both get the same error message, so neither the timing nor the message reveals which
   usernames exist.
4. **Minimum password length is 6.** This is shorter than NIST SP 800-63B's 8, by the owner's
   choice. The server only listens on 127.0.0.1 and sign-in is rate-limited, so guessing is
   slow. Raise `MIN_PASSWORD` before exposing the UI beyond the local machine.
5. **Sign-in is rate-limited per client address and per account**, 10 attempts a minute each, so
   spreading guesses across addresses doesn't help. Successful sign-ins are audited
   (`user.login`). Failed ones are logged with the username and address.
6. **Sessions are bound to the password.** The signed cookie (`tl_user`) holds the user id, the
   expiry and a fingerprint of the current password hash. Changing the password or disabling the
   account ends every existing session at once. Old key-based cookies (`tl_session`) are simply
   ignored.
7. **Accounts are managed from the command line** in the stack, never on a web page:
   `.\tl user NAME ROLE` (it prompts twice; the password reaches the container on stdin, never
   on a command line), `.\tl passwd NAME`, and `.\tl users role|disable|enable|list`. Each change
   is audited (`user.create/password/role/disable/enable`).

## Consequences
* There is no self-service sign-up or password reset. An admin with shell access runs
  `.\tl passwd`. That fits a small team and keeps the attack surface small.
* No MFA yet. Before the UI is reachable from other machines, add TOTP and serve it over HTTPS
  (the cookie is marked `Secure` automatically when the request is HTTPS).
