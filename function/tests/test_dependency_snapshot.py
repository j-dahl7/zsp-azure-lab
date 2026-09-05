import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dependency_snapshot', ROOT / 'scripts/dependency_snapshot.py')
snapshot_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot_module)


class DependencySnapshotTests(unittest.TestCase):
    def report(self):
        return {'version': '1', 'install': [
            {'metadata': {'name': 'azure-functions', 'version': '1.24.0'},
             'download_info': {'archive_info': {'hashes': {'sha256': 'a' * 64}}}},
            {'metadata': {'name': 'h2', 'version': '4.4.1'},
             'download_info': {'url': 'https://private.invalid/?token=do-not-submit',
                               'archive_info': {'hashes': {'sha256': 'b' * 64}}}},
        ]}

    def build(self, report):
        return snapshot_module.build_snapshot(report, repository='j-dahl7/zsp-azure-lab', sha='a' * 40,
                                              ref='refs/heads/main', run_id='1-1',
                                              direct_names={'azure-functions'}, scanned='2026-09-04T00:00:00Z')

    def test_resolved_versions_override_the_same_entrypoint_manifest_without_raw_metadata(self):
        snapshot = self.build(self.report())
        manifest = snapshot['manifests']['function/requirements.txt']
        self.assertEqual(manifest['file']['source_location'], 'function/requirements.txt')
        self.assertEqual(manifest['resolved']['h2'], {
            'package_url': 'pkg:pypi/h2@4.4.1', 'relationship': 'indirect', 'scope': 'runtime'})
        self.assertEqual(manifest['resolved']['azure-functions']['relationship'], 'direct')
        self.assertNotIn('do-not-submit', str(snapshot))
        self.assertEqual(snapshot['job']['correlator'], 'zsp-hash-locked-runtime')

    def test_incomplete_or_ambiguous_install_evidence_is_rejected(self):
        variants = [dict(version='1', install=[]), dict(version='2', install=self.report()['install'])]
        no_hash = self.report()
        no_hash['install'][0]['download_info']['archive_info']['hashes'] = {}
        variants.append(no_hash)
        duplicate = self.report()
        duplicate['install'].append(copy.deepcopy(duplicate['install'][0]))
        variants.append(duplicate)
        invalid_name = self.report()
        invalid_name['install'][0]['metadata']['name'] = '../unexpected'
        variants.append(invalid_name)
        for report in variants:
            with self.subTest(report=report):
                with self.assertRaises(ValueError):
                    self.build(report)

    def test_submission_permissions_are_isolated_from_pr_execution(self):
        source = (ROOT / '.github/workflows/validate.yml').read_text(encoding='utf-8')
        validate, submit = source.split('  submit-dependencies:', 1)
        self.assertNotIn('contents: write', validate)
        self.assertIn('needs: validate', submit)
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", submit)
        self.assertIn('contents: write', submit)
        self.assertNotIn('actions/checkout', submit)
        self.assertIn('dependency-graph/snapshots', submit)
        self.assertIn('--require-hashes -r function/requirements.txt', validate)
        self.assertIn('--ignore-installed --report', validate)

    def test_installed_version_drift_is_rejected_before_submission(self):
        with patch.object(snapshot_module.importlib.metadata, 'version', return_value='0.0.0'):
            with self.assertRaisesRegex(ValueError, 'Installed environment differs'):
                snapshot_module.verify_installed(self.report())


if __name__ == '__main__':
    unittest.main()
