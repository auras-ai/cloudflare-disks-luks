"""Release regression: allowlisted files, link refusal and tamper detection."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release', Path(__file__).resolve().parents[1] / 'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_allowlist_excludes_deployment_secrets_and_arbitrary_new_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in [*release.COMMON, *release.SOURCE, 'LICENSE-PENDING.md']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('public placeholder')
            for name in ['secrets/r2-credentials.json', '.empryo/history.json', 'installer/token.py',
                         'docs/DEVELOPMENT-NOTES.md', 'state/secrets.toml', 'local.luks', 'target/debug/secrets']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('SECRET_CANARY_DO_NOT_RELEASE')
            files = release.payload(root, source=True)
            self.assertNotIn(b'SECRET_CANARY', b''.join(files.values()))
            self.assertNotIn('installer/token.py', files)
            (root / 'README.md').unlink()
            (root / 'README.md').symlink_to(root / 'secrets/r2-credentials.json')
            with self.assertRaises(ValueError):
                release.payload(root, source=True)

    def test_archive_manifest_permissions_and_byte_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.tar.gz'
            release.write_archive(path, 'candidate', {'setup': b'public installer', 'README.md': b'read me'},
                                  version='0.2.0-rc.1', kind='source', licensed=False)
            result = release.verify_archive(path)
            self.assertEqual(result['files']['setup']['mode'], '0755')
            self.assertFalse(result['project_license_selected'])
            with tarfile.open(path, 'r:gz') as archive:
                members = [(member, archive.extractfile(member).read()) for member in archive.getmembers()]
            bad = Path(temporary) / 'tampered.tar.gz'
            with tarfile.open(bad, 'w:gz') as archive:
                for member, data in members:
                    if member.name.endswith('/setup'):
                        data = b'modified installer'
                        member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            with self.assertRaises(ValueError):
                release.verify_archive(bad)

    def test_allowlist_is_complete_for_all_shipped_installer_imports(self):
        files = release.payload(release.ROOT, source=True)
        for name in release.INSTALLER:
            compile(files['installer/' + name + '.py'], name, 'exec')
        self.assertIn('.github/workflows/release.yml', files)


if __name__ == '__main__':
    unittest.main()
