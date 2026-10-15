# ADR 0017: Team management, two-factor authentication, and audit viewer in Argus

Date: 2026-10-14 · Status: accepted · Extends ADR 0007, 0010, 0013–0016

## Context
Argus unified ReconX and ThreatLens into a single operational interface. However, identity and access administration remained fragmented:
1. User provisioning, password resets, and account disabling required command-line shell access (`.\tl user`, `.\tl passwd`), slowing emergency containment and preventing team self-service.
2. Sign-in relied solely on single-factor passwords, leaving analyst sessions vulnerable to credential stuffing and phishing.
3. While security-sensitive actions (block enforcement, allowlists, scan approvals, role changes) were recorded into the database `audit` table, operators had no in-app search, filtering, or export interface to investigate incidents or demonstrate compliance.

## Decisions

### 1. In-App User Management (`/settings?tab=team`)
* **Role-Based Access Control**:
  * `admin`: Manage users, configure SSO, change policy, reset 2FA, view audits.
  * `analyst`: Run scans, approve blocks, manage cases, add indicators.
  * `viewer`: Read-only access to threat intelligence and recon results.
* **Safety & Invariants**:
  * An administrator cannot disable their own account.
  * The sole administrator of a deployment cannot be demoted to analyst or viewer.
  * Passwords must meet security standards (minimum 10 characters).
  * Password changes immediately invalidate existing user sessions via salt rotation and cookie invalidation.

### 2. Two-Factor Authentication (RFC 6238 TOTP) & Single Sign-On
* **Native TOTP Engine**:
  * Implemented using standard library `hmac`, `hashlib`, and `struct` conforming strictly to RFC 6238 (30-second window, HMAC-SHA1, 6 digits).
  * Setup generates a cryptographically random Base32 secret (`totp.generate_secret()`) and standard `otpauth://` URI.
* **Air-Gapped QR Code Rendering**:
  * Generates pure inline SVG strings (`totp.qr_svg()`) using `qrcode.image.svg.SvgPathImage`. No external third-party CDN or canvas scripts required.
  * Displayed directly in Argus settings with copyable secret keys for manual input into authenticators (1Password, Google Authenticator, Bitwarden).
* **Two-Stage Sign-In**:
  * `POST /app/api/session` validates login and password. If TOTP is enabled and no code is supplied, responds with `{ "ok": false, "totp_required": true }`.
  * The frontend smoothly transitions to the 6-digit TOTP verification screen.
  * Admins have emergency override capabilities (`POST /settings/users/{id}/reset-2fa`) audited to the event log.
* **SSO Framework**:
  * Support for Google Workspace, Microsoft Entra ID, and Okta OIDC.
  * Secrets are encrypted/redacted with `********` on read.
  * Mock provider endpoint (`/auth/sso/mock`) supports deterministic dev and CI testing.

### 3. Searchable Audit Log Viewer (`/audit` or `/settings?tab=audit`)
* **Structured Query & Navigation**:
  * Categorized filtering pills (`All`, `Blocks`, `Scans`, `Users`, `Policy`, `Auth`, `Cases`) with real-time incident counters.
  * Search across actors, action verbs, target values, and details JSON.
  * Actor dropdown filter to quickly review actions taken by a specific team member.
* **Inspection & Compliance Export**:
  * Interactive modal displaying the full formatted event details and raw JSON payload.
  * Streaming CSV export (`GET /settings/audit/export`) featuring sanitized cell formatting to prevent formula injection attacks in spreadsheet tools.

## Consequences
* Team provisioning, role adjustment, and credential revocation can be executed in seconds from the Argus UI without terminal access.
* Strong multi-factor authentication protects high-clearance threat intelligence and recon assets.
* Operational actions across ReconX and ThreatLens are fully visible, searchable, and exportable for compliance.
