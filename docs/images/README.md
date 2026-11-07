# Images used by the documentation

Drop images for `README.md` and the pages under `docs/` here, and reference them with a path
relative to the file that uses them:

```markdown
![Alt text that describes the picture](docs/images/example.png)     <!-- from README.md -->
![Alt text that describes the picture](images/example.png)          <!-- from docs/*.md -->
```

Conventions:

- **SVG** for logos, icons and diagrams — crisp at any size, tiny in git.
- **PNG or WebP** for screenshots. Compress them; keep each file under ~300 KB.
- Name files for what they show, in lower case with dashes: `architecture.svg`,
  `admin-api-screenshot.png`.
- Always write alt text; it is what screen readers and search engines see.
- Cap the displayed size instead of shipping a huge file:
  `<img src="docs/images/architecture.svg" alt="Component diagram" width="720">`.
- For a banner that must work on light and dark themes, use a `<picture>` element with
  `prefers-color-scheme` sources rather than a single image with baked-in colours.
