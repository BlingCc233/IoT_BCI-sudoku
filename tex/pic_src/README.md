# Project figures (build sources)

This folder contains the TikZ sources for the project-specific PDFs under `tex/pic/`.

Build on macOS/Linux (requires `xelatex`):

```bash
xelatex -interaction=nonstopmode -halt-on-error -output-directory=../pic pica.tex
xelatex -interaction=nonstopmode -halt-on-error -output-directory=../pic picb.tex
xelatex -interaction=nonstopmode -halt-on-error -output-directory=../pic picc.tex
xelatex -interaction=nonstopmode -halt-on-error -output-directory=../pic picd.tex
xelatex -interaction=nonstopmode -halt-on-error -output-directory=../pic pice.tex
```

