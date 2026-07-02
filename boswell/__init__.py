__version__ = "0.1.0"

import os as _os
from pathlib import Path as _Path

_dotenv = _Path.home() / ".boswell" / ".env"
if _dotenv.exists():
    for _line in _dotenv.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            _os.environ.setdefault(_k.strip(), _v.strip())
