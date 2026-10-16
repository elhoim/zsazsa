"""Writes config/__init__.py in the container.

Without arguments, as the entrypoint calls it, it creates the config when it is
missing. setup.sh passes its answers on standard input, separated by NUL bytes,
which keeps the keys out of the process list:

    printf '%s\\0' [--import FILE] KEY=VALUE... | python docker/configure.py -
"""

import ast
import os
import re
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.atomic_write import write_atomically

CONFIG = Path("config/__init__.py")
EXAMPLE = Path("/opt/zsazsa/config/__init__.py.example")
if not EXAMPLE.exists():
    EXAMPLE = ROOT / "config" / "__init__.py.example"

# Everything else is written as a string. A VERIFYCERT has to be a real bool:
# PyMISP takes a string there for the path of a CA bundle.
INT_KEYS = re.compile(r"^PORT$|_PORT$|_DB$")
BOOL_KEYS = re.compile(r"_VERIFYCERT$|_ENABLED$|^MISP_SESSION_REDIRECT_TO_LOGIN$")


def create():
    """The example with a SECRET_KEY of its own, as docs/install.sh does."""
    text, count = re.subn(r"^SECRET_KEY = .*", f"SECRET_KEY = {secrets.token_hex(32)!r}",
                          EXAMPLE.read_text(), count=1, flags=re.M)
    if not count:
        sys.exit(f"{EXAMPLE} has no SECRET_KEY line to replace")
    fd, tmp = tempfile.mkstemp(dir=CONFIG.parent, suffix=".tmp")
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    # The webapp, analyser and collector start together on the same volume.
    # Linking fails when the file exists, so exactly one of them creates it.
    try:
        os.link(tmp, CONFIG)
        print("Created config/__init__.py with a generated SECRET_KEY.")
    except FileExistsError:
        pass
    finally:
        os.unlink(tmp)


def value(key, raw):
    if INT_KEYS.search(key):
        return int(raw)
    if BOOL_KEYS.search(key):
        return raw.lower() in ("1", "true", "yes", "y")
    return raw


def put(text, key, new):
    """KEY = new, in place of the lines the config assigns it on, or at the end."""
    line = f"{key} = {new!r}"
    node = next((n for n in ast.parse(text).body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == key for t in n.targets)), None)
    if node is None:
        return text.rstrip("\n") + f"\n{line}\n"
    lines = text.split("\n")
    lines[node.lineno - 1:node.end_lineno] = [line]
    return "\n".join(lines)


def main(args):
    if args == ["-"]:
        # printf '%s\0' with nothing to pass still writes one empty item.
        args = [a for a in sys.stdin.read().split("\0") if a]
    if args[:1] == ["--import"]:
        text = Path(args[1]).read_text()
        if CONFIG.exists():
            shutil.copy2(CONFIG, CONFIG.with_name("__init__.py.backup"))
        write_atomically(CONFIG, text)
        print("Imported the configuration.")
        args = args[2:]
    elif not CONFIG.exists():
        create()

    if not args:
        return
    text = CONFIG.read_text()
    for pair in args:
        key, _, raw = pair.partition("=")
        text = put(text, key, value(key, raw))
    write_atomically(CONFIG, text)
    print("Set " + ", ".join(pair.partition("=")[0] for pair in args) + ".")


if __name__ == "__main__":
    main(sys.argv[1:])
