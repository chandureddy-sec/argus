# AED — lab agent gateway (endpoint detection)

**Lab only.** AED is an experimental, sandboxed learning track: agents on **lab
VMs** ship normalized OCSF telemetry over mutual TLS to a gateway that runs
**separately** from the rest of Argus. It is **disabled by default** and must
never monitor company endpoints, carry real alerts, or bind to a company
network. Usernames are hashed and secrets scrubbed before anything is stored.

The gateway is its own process (`threatlens.aed.serve`), never mounted on the
`:8000` API. The `:8000` UI reaches it only through a read-only admin proxy.

---

## 1. Enable it (opt-in)

1. **Build the Linux agent** (static, lab VM arch):
   ```bash
   cd "<repo>" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o threatlens/aed-agent ./cmd/aed-agent
   ```
2. **Set lab config in `threatlens/.env`:**
   ```ini
   TL_SECRET_KEY=<already set>            # seals the AED CA key
   AED_ADMIN_TOKEN=<a long random string> # the :8000 UI uses this to read the gateway
   AED_ADVERTISE_URL=https://<lab-ip>:8443 # how lab VMs reach the gateway
   AED_BIND_HOST_PUBLISH=<lab-ip>          # host interface to publish 8443 on (default 127.0.0.1)
   AED_TRUST_CERT_HEADER=true              # only when a TLS/mTLS terminator is in front (see §3)
   # Point the :8000 UI at the gateway admin proxy:
   TL_AED_ADMIN_URL=http://127.0.0.1:8443
   TL_AED_ADMIN_TOKEN=<same as AED_ADMIN_TOKEN>
   ```
3. **Start the gateway (opt-in profile):**
   ```bash
   cd threatlens && docker compose --profile aed up -d --build aed-gateway
   ```
   Restart the `api` service after setting `TL_AED_ADMIN_*` so the UI picks them up.

The **Response → Lab endpoints** page shows a 503 "not configured" state until
`TL_AED_ADMIN_URL`/`TL_AED_ADMIN_TOKEN` are set and the gateway is reachable.

---

## 2. Network safety — bind to the lab interface only

- **Exposure is the host-published address**, `AED_BIND_HOST_PUBLISH` (default
  `127.0.0.1`). The container listens on `0.0.0.0` *inside* its own namespace;
  what the network sees is only the published address. Set it to the **lab
  interface IP**, e.g. `10.0.0.5`. **Never `0.0.0.0`** on a machine attached to a
  company network.
- **Docker port mapping:** `AED_BIND_HOST_PUBLISH:8443 → 8443`. Confirm with
  `docker compose --profile aed port aed-gateway 8443` — it must print the lab IP,
  not `0.0.0.0`.
- **Host firewall:** allow inbound `8443/tcp` **only from the lab subnet**. Example (ufw):
  ```bash
  sudo ufw allow from 10.0.0.0/24 to any port 8443 proto tcp
  sudo ufw deny 8443/tcp
  ```

---

## 3. mTLS terminator (required for agent traffic)

The gateway authenticates agents by their **client certificate**, but trusts the
cert only when a TLS terminator in front verifies it and forwards it in
`X-AED-Client-Cert` (set `AED_TRUST_CERT_HEADER=true`). Without a terminator the
gateway still serves `/aed/healthz` and the admin endpoints, but `ingest`/
`heartbeat` return 401. Example nginx terminator:

```nginx
server {
    listen 10.0.0.5:8443 ssl;
    ssl_certificate     /etc/nginx/aed/server.crt;      # a server cert for <lab-ip>
    ssl_certificate_key /etc/nginx/aed/server.key;
    ssl_client_certificate /etc/nginx/aed/ca.crt;       # the AED CA (var/lib/aed/ca/ca.crt)
    ssl_verify_client on;                               # mutual TLS
    location / {
        proxy_pass http://127.0.0.1:8443;               # the gateway, loopback only
        proxy_set_header X-AED-Client-Cert $ssl_client_escaped_cert;
        proxy_set_header X-AED-Seq   $http_x_aed_seq;
        proxy_set_header X-AED-Nonce $http_x_aed_nonce;
    }
}
```
Publish the gateway on loopback (`AED_BIND_HOST_PUBLISH=127.0.0.1`) when nginx
fronts it, and open `8443` (nginx) to the lab subnet instead.

---

## 4. Onboard an endpoint

1. **Response → Lab endpoints → Add endpoint** (admin): pick **Linux**, optional
   name/group → the gateway mints a **single-use, 15-minute** enrollment token,
   shown **once**, with the **install command** and the **CA fingerprint**.
2. On the lab VM, paste the install command. It downloads the agent, **verifies
   its SHA-256**, installs it, writes a `0600` config, pins the **CA fingerprint**,
   enrolls (token → client cert), installs the systemd unit and starts.
3. The endpoint appears **Online** on its first heartbeat.

The token is stored only as an HMAC and never logged; it redeems exactly once.

---

## 5. Lab demo — fresh Ubuntu VM  *(Untested here: no lab VM in this environment)*

1. Two lab VMs on the lab network: **A** (runs the Argus stack + gateway), **B**
   (the attacker).
2. On A: enable AED (§1), open **Add endpoint → Linux**, copy the install command.
3. On a third VM **C** (the monitored endpoint): paste the install command; it
   verifies the checksum and enrolls. **Lab endpoints** shows C **Online**.
4. From B, make several **failed SSH logins** to C:
   ```bash
   for i in $(seq 1 12); do ssh baduser@<C-ip> -o PreferredAuthentications=password -o StrictHostKeyChecking=no true; done
   ```
5. Within the rule window, **Lab endpoints → Detections** shows an
   `ssh-bruteforce` alert for C with the source IP, count and evidence.

---

## 6. Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `AED_GATEWAY_ENABLED` | `false` | Master switch; `ingest`/`enroll` are 503 until true |
| `AED_BIND_HOST_PUBLISH` | `127.0.0.1` | **Host** interface the gateway is published on — the lab IP |
| `AED_GATEWAY_PORT` | `8443` | Gateway port |
| `AED_ADVERTISE_URL` | — | URL endpoints use to reach the gateway (in the install command) |
| `AED_ADMIN_TOKEN` | — | Bearer token for the admin endpoints; held server-side by the `:8000` proxy |
| `AED_TRUST_CERT_HEADER` | `false` | Trust `X-AED-Client-Cert` from the terminator — **only** behind one |
| `AED_AGENT_PATH` | — | Path to the served Linux agent inside the gateway (`/opt/aed/aed-agent`) |
| `AED_CA_DIR` | `/var/lib/aed/ca` | Where the CA cert + **sealed** key persist |
| `AED_SECRET_KEY` / `TL_SECRET_KEY` | — | Seals the CA private key |
| `TL_AED_ADMIN_URL` / `TL_AED_ADMIN_TOKEN` | — | The `:8000` UI → gateway admin proxy |

Out of scope this phase: Windows/macOS agents, response actions, auto-update,
advanced detection.
