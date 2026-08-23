# SpinfoSecurity GitHub Pages site

Source mirror for [spinfosecurity.github.io](https://spinfosecurity.github.io). Deploy by copying these files into the `spinfosecurity/spinfosecurity.github.io` repository root and pushing to `main`.

Also see **`GITHUB-PROFILE-README.md`** — copy to the org profile repo (`spinfosecurity/spinfosecurity`) for a pinned GitHub profile README.

```bash
./scripts/sync-portfolio-site.sh /path/to/spinfosecurity.github.io
cd /path/to/spinfosecurity.github.io && git add -A && git commit -m "Update portfolio" && git push
```

Or trigger the **Deploy portfolio site** GitHub Action after adding `PAGES_DEPLOY_TOKEN` secret.
