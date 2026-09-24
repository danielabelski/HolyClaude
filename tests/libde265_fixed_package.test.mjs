import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

test('requires the fixed Bookworm libde265 runtime package in every candidate', () => {
  const dockerfile = readFileSync('Dockerfile', 'utf8');
  const runtimeChecks = readFileSync('tests/browser_runtime_container_checks.sh', 'utf8');

  assert.match(dockerfile, /RUN apt-get update && apt-get upgrade -y/);
  assert.match(
    runtimeChecks,
    /require_eq "libde265 runtime package version" "\$\(dpkg-query -W -f='\$\{Version\}' libde265-0\)" "1\.0\.11-1\+deb12u3"/,
  );
});

test('does not carry exceptions for the superseded libde265 package', () => {
  const ledger = JSON.parse(readFileSync('security/advisory-reviews.json', 'utf8'));
  const stale = ledger.reviews.filter((review) =>
    review.component?.versions?.includes('1.0.11-1+deb12u2') &&
    review.component?.names?.some((name) => name.startsWith('libde265')),
  );
  assert.deepEqual(stale, []);
});
