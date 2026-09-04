"""Describe the hash-verified pip install; never submit to GitHub from this script."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import re
from urllib.parse import quote


def canonical_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', value):
        raise ValueError('Invalid package name in install evidence')
    return re.sub(r'[-_.]+', '-', value).lower()


def build_snapshot(report, *, repository, sha, ref, run_id, direct_names, scanned):
    if report.get('version') != '1' or not isinstance(report.get('install'), list) or not report['install']:
        raise ValueError('Expected a nonempty pip installation report v1')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository identity')
    if not re.fullmatch(r'[a-f0-9]{40}', sha) or not ref.startswith('refs/'):
        raise ValueError('Invalid commit/ref identity')
    resolved = {}
    for entry in report['install']:
        metadata = entry.get('metadata', {})
        name = canonical_name(metadata.get('name'))
        version = metadata.get('version')
        digest = entry.get('download_info', {}).get('archive_info', {}).get('hashes', {}).get('sha256')
        if not isinstance(version, str) or not version or len(version) > 100 or re.search(r'\s', version):
            raise ValueError('Invalid package version in install evidence')
        if not isinstance(digest, str) or not re.fullmatch(r'[a-fA-F0-9]{64}', digest):
            raise ValueError('Installed archive is missing its SHA-256 evidence')
        if name in resolved:
            raise ValueError('Duplicate package identity in install evidence')
        resolved[name] = {
            'package_url': f'pkg:pypi/{quote(name, safe="")}@{quote(version, safe="")}',
            'relationship': 'direct' if name in direct_names else 'indirect',
            'scope': 'runtime',
        }
    return {
        'version': 0,
        'sha': sha,
        'ref': ref,
        'job': {'id': run_id, 'correlator': 'zsp-hash-locked-runtime'},
        'detector': {'name': 'zsp-pip-install-report', 'version': '1.0.0',
                     'url': f'https://github.com/{repository}'},
        'scanned': scanned,
        'manifests': {'function/requirements.txt': {
            'name': 'function/requirements.txt',
            'file': {'source_location': 'function/requirements.txt'},
            'resolved': dict(sorted(resolved.items())),
        }},
    }


def verify_installed(report):
    for entry in report['install']:
        metadata = entry['metadata']
        if importlib.metadata.version(metadata['name']) != metadata['version']:
            raise ValueError('Installed environment differs from pip install evidence')
    # GHSA-6hr6-w5qg-qmwg was fixed in h2 4.4.1. Exercise the real installed
    # library as well as its distribution metadata; no connection is opened.
    import h2
    import h2.connection
    version = h2.__version__
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or tuple(map(int, version.split('.'))) < (4, 4, 1):
        raise ValueError('h2 runtime must be a reviewed stable version at least 4.4.1')
    connection = h2.connection.H2Connection()
    connection.initiate_connection()
    if not connection.data_to_send():
        raise ValueError('h2 runtime initialization did not produce protocol data')
    return version


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True, type=Path)
    arguments = parser.parse_args()
    report = json.loads(arguments.report.read_text(encoding='utf-8'))
    direct = set()
    requirements = Path(__file__).resolve().parents[1] / 'function/requirements.in'
    for line in requirements.read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            match = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)', line)
            if not match:
                raise ValueError('Unsupported direct requirement declaration')
            direct.add(canonical_name(match.group(1)))
    snapshot = build_snapshot(
        report, repository=os.environ['GITHUB_REPOSITORY'], sha=os.environ['GITHUB_SHA'],
        ref=os.environ['GITHUB_REF'], run_id=f"{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}",
        direct_names=direct, scanned=datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
    )
    h2_version = verify_installed(report)
    encoded = json.dumps(snapshot, separators=(',', ':'))
    if len(encoded.encode('utf-8')) > 60 * 1024:
        raise ValueError('Dependency snapshot exceeds the bounded job-output budget')
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
        output.write(f'snapshot={encoded}\n')
    count = len(snapshot['manifests']['function/requirements.txt']['resolved'])
    print(f'Verified installed h2 {h2_version}; prepared {count} hash-verified runtime dependencies.')


if __name__ == '__main__':
    main()
