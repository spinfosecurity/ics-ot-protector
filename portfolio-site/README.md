# SpinfoSecurity GitHub Pages site

Source mirror for [spinfosecurity.github.io](https://spinfosecurity.github.io). Deploy by copying these files into the `spinfosecurity/spinfosecurity.github.io` repository root and pushing to `main`.

```bash
rsync -av --delete portfolio-site/ /path/to/spinfosecurity.github.io/
cd /path/to/spinfosecurity.github.io
git add -A && git commit -m "Improve portfolio readability and SEO" && git push
```

GitHub Pages serves from that repo automatically; no build step required.
