import json
import os
from pathlib import Path
import tempfile
import unittest

class ArtifactTests(unittest.TestCase):
    def test_writes_readable_report_and_hash(self):
        from yf_tools.report_artifact import save
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json'
            result=save(path,{'status':'observed'})
            self.assertEqual(json.loads(path.read_text()),{'status':'observed'})
            self.assertEqual(result['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            if os.name == 'posix': self.assertEqual(path.stat().st_mode & 0o777,0o600)
    def test_refuses_overwrite(self):
        from yf_tools.report_artifact import save
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json';path.write_text('original')
            with self.assertRaises(FileExistsError): save(path,{'status':'new'})
            self.assertEqual(path.read_text(),'original')
    def test_no_partial_file_on_serialization_failure(self):
        from yf_tools.report_artifact import save
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json'
            with self.assertRaises(TypeError): save(path,{'invalid':object()})
            self.assertFalse(path.exists())
    def test_refuses_symlink_destination(self):
        from yf_tools.report_artifact import save
        with tempfile.TemporaryDirectory() as directory:
            original=Path(directory)/'original';original.write_text('keep')
            link=Path(directory)/'link';link.symlink_to(original)
            with self.assertRaises(FileExistsError):save(link,{'status':'new'})
            self.assertEqual(original.read_text(),'keep')
