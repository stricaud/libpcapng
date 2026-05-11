import sys, os

# Make the in-tree libpcapng Python package importable for autodoc.
# The .so must have been built first (cmake --build build).
sys.path.insert(0, os.path.abspath("../../bindings/python"))

project   = "libpcapng pcapsh"
author    = "libpcapng contributors"
copyright = "2024, libpcapng contributors"
release   = "1.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
]

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

html_theme = "furo"
html_static_path = ["_static"]
autodoc_member_order = "bysource"
