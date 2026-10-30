# Running a public PublicLocal instance

This is how the free server at `publiclocal.app` is set up. The same steps work for any open instance you want to run for others.

## What `--public` changes

| Safeguard | Default | Flag to change it |
|---|---|---|
| Browser warning page; unlocks after 3 seconds, remembered per tunnel for 24h | on | always on |
| Random subdomains only (no `paypal-login.publiclocal.app`) | on | always on |
| TCP tunnels | off | always off |
| Link lifetime (same address across reconnects) | 24h, 7 days signed in | `--max-tunnel-age`, `--account-tunnel-age` |
| Sessions per client IP | 3 | `--max-per-ip` |
| Requests per minute per tunnel | 600 | `--rate` |
| Traffic per session | 2 GB | `--max-transfer-mb` |
| Request body size | 10 MB | |
| `X-Robots-Tag: noindex` on all tunnel responses | on | |
| "Report abuse" link on the warning page | required | `--abuse-contact` |
| Random names, 6–8 letters and digits without vowels (never spells a word) | on | |
| Misuse checker: fetches random live links and flags phishing-like pages | every 10 min, 5 links | `--scan-interval` |
| GitHub sign-in: accounts younger than 30 days are refused | on when an OAuth app is set | |
| Warning cookie is signed per link; the continue form only works from the link's own page; the app cannot set cookies for the whole domain | on | |
| Active links per client network (IPv4 address or IPv6 /64) and per signed-in account | 10 / 50 | `--max-links-per-ip`, `--max-links-per-account` |
| Client connections per network per minute | 30 | `--connects-per-minute` |
| Plain HTTP redirects to HTTPS; certificate challenges on tunnel names are refused | on | |

API clients, webhooks and `curl` never see the warning page: it is shown only to browsers (`Mozilla` user agent asking for HTML). Developers can also skip it with the header `PublicLocal-Skip-Warning: 1`.

## 1. DNS on Cloudflare

1. Add the domain to Cloudflare (free plan) and switch the registrar's nameservers to Cloudflare's.
2. Add two records, **DNS only (grey cloud)**, not proxied:
   ```
   A  publiclocal.app    <server IP>
   A  *.publiclocal.app  <server IP>
   ```
3. Create an API token: *My Profile → API Tokens → Create Token → Edit zone DNS*, limited to this one zone. Keep it secret.

## 2. Server

Any small VPS works (2 vCPU, 2–4 GB RAM). Bandwidth is what matters. On Ubuntu or Debian:

```bash
curl -fsSL https://publiclocal.app/install.sh | sh
sudo useradd --system --home /var/lib/publiclocal --create-home publiclocal
sudo ufw allow 22,80,443,7000/tcp && sudo ufw enable
```

`/etc/publiclocal.env` (mode 600, owned by root):

```
CLOUDFLARE_DNS_API_TOKEN=your-token
GITHUB_CLIENT_ID=your-oauth-app-client-id
GITHUB_CLIENT_SECRET=your-oauth-app-client-secret
```

The GitHub lines enable `publiclocal login` (see step 3); leave them out to run without accounts.

`/etc/systemd/system/publiclocal.service`:

```ini
[Unit]
Description=PublicLocal public tunnel server
After=network-online.target
Wants=network-online.target

[Service]
User=publiclocal
WorkingDirectory=/var/lib/publiclocal
EnvironmentFile=/etc/publiclocal.env
ExecStart=/usr/local/bin/publiclocal server \
  --public \
  --domain publiclocal.app \
  --acme-email you@example.com \
  --abuse-contact mailto:abuse@publiclocal.app \
  --ban-file /var/lib/publiclocal/bans.txt \n  --state-file /var/lib/publiclocal/state.json \n  --site-dir /var/lib/publiclocal/site
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now publiclocal
journalctl -u publiclocal -f
```

The first start requests one wildcard certificate (`publiclocal.app` + `*.publiclocal.app`) through Cloudflare DNS. It takes a minute or two, is cached in `publiclocal-certs/`, and renews automatically 30 days before expiry.

## 3. GitHub sign-in (optional)

Signed-in users get 7-day links they can extend. Create an OAuth app at *GitHub → Settings → Developer settings → OAuth Apps → New OAuth App*:

| Field | Value |
|---|---|
| Application name | PublicLocal |
| Homepage URL | `https://publiclocal.app` |
| Authorization callback URL | `https://publiclocal.app/auth/callback` |

Then *Generate a new client secret*, and put the client ID and secret in `/etc/publiclocal.env`. Signing in works like a device login: `publiclocal login` prints a code, the browser page asks the user to type it, and only then goes to GitHub, so a login link sent to someone else is useless without the code. No scopes are requested: the server only reads the public profile (login, ID, account age) and throws the GitHub access token away. Links and accounts are stored in `--state-file`, so they survive restarts and upgrades.

## 4. Handling abuse

Logs record which client IP opened which tunnel URL (`journalctl -u publiclocal | grep "tunnel open"`), which is what you need to answer reports from your hosting provider.

On the server:

```bash
publiclocal admin list                 # who is connected, with URLs and traffic
publiclocal admin kill k7xq2m      # close the session behind a subdomain
publiclocal admin ban 203.0.113.45     # ban an IP and close its sessions (saved to the ban file)
publiclocal admin unban 203.0.113.45
publiclocal admin bans
publiclocal admin flags                # links the misuse checker flagged
publiclocal admin scan                 # check a random sample of live links now
publiclocal admin suspend k7xq2m       # remove a link and ban its IP and GitHub account
publiclocal admin unban-user octocat
```

The misuse checker only flags; a person decides. Flags are logged as `possible misuse flagged`, so `journalctl -u publiclocal -f | grep flagged` shows them as they happen.

The admin API listens on `127.0.0.1:7001` only and refuses requests made by a browser. Set `--admin-token` (env `PUBLICLOCAL_ADMIN_TOKEN`) to require a token as well, and give it to `publiclocal admin --token` or the same env var.

Set up the abuse mailbox you list in `--abuse-contact` and read it. Hosting providers (OVH included) suspend servers whose owners ignore abuse reports.

## 5. CAA record

Add a CAA record so only your own Let's Encrypt account can issue certificates for the domain and its tunnels. The account address is in the log at first start (`journalctl -u publiclocal | grep "acme account"`):

```
CAA  publiclocal.app  0 issue     "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<your id>"
CAA  publiclocal.app  0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<your id>"
```

## 6. Public Suffix List

Without this, a single phishing report can get the **whole** domain blocked by browsers and Google Safe Browsing, taking every user's tunnel down with it. Listing `publiclocal.app` on the [Public Suffix List](https://publicsuffix.org) makes each subdomain its own site to browsers and blocklists, and isolates cookies between tunnels.

1. Add a TXT record proving ownership. The PR number comes from step 2, so add it right after opening the PR:
   ```
   TXT  _psl.publiclocal.app  "https://github.com/publicsuffix/list/pull/<PR number>"
   ```
2. Fork [publicsuffix/list](https://github.com/publicsuffix/list) and add to the PRIVATE DOMAINS section of `public_suffix_list.dat`, in alphabetical order by organization:
   ```
   // PublicLocal : https://github.com/sevenoways/publiclocal
   // Submitted by <your name> <you@example.com>
   publiclocal.app
   ```
3. Open the PR and fill in their template: who you are, that the domain hosts user-controlled subdomains (tunnels), and that you've read their guidelines. Review can take several weeks, and the domain must stay registered for at least two more years.
