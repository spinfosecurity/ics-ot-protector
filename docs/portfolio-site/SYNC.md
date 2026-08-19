# Portfolio site sync

These files mirror [spinfosecurity.github.io](https://spinfosecurity.github.io/). After merging doc updates to `main`, copy them into the Pages repo:

```bash
git clone https://github.com/spinfosecurity/spinfosecurity.github.io.git
rsync -av docs/portfolio-site/ spinfosecurity.github.io/ --exclude GITHUB-PROFILE-README.md --exclude SYNC.md
cd spinfosecurity.github.io && git add -A && git commit -m "docs: sync from monorepo portfolio-site" && git push
```

Update the GitHub org profile README from `GITHUB-PROFILE-README.md`:

```bash
cp docs/portfolio-site/GITHUB-PROFILE-README.md ../spinfosecurity/README.md
```

Requires org/repo write access (not available to the cloud agent bot).
