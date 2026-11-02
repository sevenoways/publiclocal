# PublicLocal GitHub Action

Expose a port from a job as a public HTTPS link. Use it to run webhook tests against a real URL, or to post a preview link on every pull request.

```yaml
- uses: sevenoways/publiclocal/action@v1
  id: tunnel
  with:
    port: 3000
    expires: 2h            # optional
    password: ${{ secrets.PREVIEW_PASSWORD }}   # optional
- run: echo "Preview at ${{ steps.tunnel.outputs.url }}"
```

`args` is passed to the client as flags, so only give it values you trust (not text from a pull request). The link is also in `$PUBLICLOCAL_URL` for later steps, and the tunnel is stopped when the job ends. Add `account: ${{ secrets.PUBLICLOCAL_ACCOUNT }}` (the token from `publiclocal login`) for 7-day links, `--domain` and `--allow-github` in `args`, or `server` and `token` for your own server.

Preview link on a pull request:

```yaml
- uses: sevenoways/publiclocal/action@v1
  id: tunnel
  with: { port: 3000, args: --allow-github @my-org --note "PR ${{ github.event.number }}" }
- uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({ ...context.repo, issue_number: context.issue.number,
        body: `Preview: ${{ steps.tunnel.outputs.url }} (while this job runs)` })
- run: sleep 1800   # keep the job, and the link, alive for 30 minutes
```
