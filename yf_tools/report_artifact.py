"""Publish restricted reports atomically without overwriting previous evidence."""
import hashlib
import json
import os
from pathlib import Path
import tempfile


def save(path, report):
    path = Path(path)
    data = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False)+'\n').encode()
    descriptor, temporary = tempfile.mkstemp(prefix='.yf-report-', dir=path.parent)
    try:
        with os.fdopen(descriptor,'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # Linking is atomic and refuses existing files including symlinks.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
    actual = path.read_bytes()
    if actual != data:
        raise OSError('report readback mismatch')
    return {'bytes':len(actual),'sha256':hashlib.sha256(actual).hexdigest()}
