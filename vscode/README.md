# PublicLocal for VS Code

Share the app you are working on with a public HTTPS link, from the command palette or the status bar. PublicLocal is an open-source ngrok alternative with a free public server and no sign-up.

**PublicLocal: Share Port** asks for the port, starts the tunnel and shows the link in the status bar. Click it to copy, open, inspect requests or stop. Requests appear in the PublicLocal output channel as they happen, and the local inspector shows headers and bodies and replays webhooks.

Options when sharing: a password, a GitHub sign-in allowlist (`--allow-github anna,@my-org`), a lifetime (`--expires 30m`), a note for visitors, and anything else the `publiclocal` client accepts.

## Requirements

The `publiclocal` client. The extension offers to install it the first time, or run:

```
curl -fsSL https://publiclocal.app/install.sh | sh        # Linux, macOS
irm https://publiclocal.app/install.ps1 | iex             # Windows
brew install sevenoways/tap/publiclocal                   # Homebrew
```

Set `publiclocal.server` to use your own server. Docs: https://publiclocal.app/docs.html
