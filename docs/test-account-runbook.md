# Manual Test-Account Runbook

Use a small number of dedicated Google test accounts that you create manually.
Do not use personal accounts or accounts belonging to anyone else.

Recommended manual workflow:

1. Create each dedicated account by hand through Google's normal UI.
2. Record the account purpose locally outside source control.
3. Keep credentials out of code, logs, screenshots, and fixtures.
4. Avoid storing real personal data in the account.
5. Isolate accounts by experiment when state separation matters.
6. Stop testing if an account triggers safety systems or exposes non-owned data.

Credential and object metadata:

- Store only secret references, such as environment variable names or external
  vault references. Do not store password, token, or cookie values in artifacts.
- Cookie metadata may record names, domains, paths, and security flags, but the
  cookie value must remain a `SecretRef`.
- Assign clear account roles such as owner, attacker, victim, admin, or viewer.
  Keep role-separated accounts distinct when validating authorization behavior.
- Owned test objects must be researcher-created, non-sensitive, and free of
  third-party data.
- Record which owned accounts may access each test object, and keep the owner
  account in that access list.

Forbidden:

- scripts for registration
- browser automation for account creation
- account farms or bulk registration
- SMS or phone quota bypass
- evasion of anti-abuse systems
- use of accounts not owned by the researcher
