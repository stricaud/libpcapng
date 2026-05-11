SPHINXBUILD = sphinx-build
SOURCEDIR   = .
BUILDDIR    = _build

.PHONY: help html clean

help:
	@$(SPHINXBUILD) -M help $(SOURCEDIR) $(BUILDDIR)

html:
	$(SPHINXBUILD) -M html $(SOURCEDIR) $(BUILDDIR) -q
	@echo "Docs built: $(BUILDDIR)/html/index.html"

clean:
	rm -rf $(BUILDDIR)
