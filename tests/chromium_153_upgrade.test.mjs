import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const dockerfile = readFileSync('Dockerfile', 'utf8');
const facts = JSON.parse(readFileSync('contracts/product-facts.json', 'utf8'));
const ledger = JSON.parse(readFileSync('security/advisory-reviews.json', 'utf8'));
const immutableInputs = readFileSync('security/immutable-inputs.yml', 'utf8');

const version = '153.0.8010.52-1~deb12u1';
const packageBindings = [
  ['CHROMIUM_PACKAGE_SHA256_AMD64', 'amd64-chromium-package-sha256', 'ac40026c10d0a8c2bb699035873ca33440566033068b1abdc19cbe7c861ff11f'],
  ['CHROMIUM_PACKAGE_SHA256_ARM64', 'arm64-chromium-package-sha256', 'a7bba2726939dfa0484dee3f9c4da46761e32a7b0ee97ffc7040be1582dc5824'],
  ['CHROMIUM_COMMON_PACKAGE_SHA256_AMD64', 'amd64-chromium-common-package-sha256', '7c674dbd4d188108904f7c4117f12ae1c7e0557ebb64ba77964c6b903bbd061a'],
  ['CHROMIUM_COMMON_PACKAGE_SHA256_ARM64', 'arm64-chromium-common-package-sha256', '9e5f90c9643dcbe2964e16d5972e4e7f76c18b1cad7845855116a4890895884d'],
  ['CHROMIUM_SANDBOX_PACKAGE_SHA256_AMD64', 'amd64-chromium-sandbox-package-sha256', '08f35c0b27fe17c985f2dca6995e9fc006f3f406534c1e8800ac15ba75df90ec'],
  ['CHROMIUM_SANDBOX_PACKAGE_SHA256_ARM64', 'arm64-chromium-sandbox-package-sha256', '0b2cf9c09495674f193e950d9af9789c3fa65ddbf40a3c5522c65cb32b74a075'],
];
const chromiumPackageNames = new Set(['chromium', 'chromium-common', 'chromium-sandbox']);
const retiredChromiumVersions = new Set([
  '151.0.7922.173-1~deb12u1',
  '152.0.7977.82-1~deb12u1',
]);

function assertImmutablePackageBindings(input) {
  for (const [, field, sha256] of packageBindings) {
    assert.match(
      input,
      new RegExp(`^    ${field}: ${sha256}$`, 'm'),
      `${field} must bind its exact signed package digest`,
    );
  }
}

test('pins the complete signed Chromium 153 package trio for both architectures', () => {
  assert.match(dockerfile, new RegExp(`ARG CHROMIUM_DEBIAN_VERSION=${version.replaceAll('.', '\\.')}`));
  for (const [name, , sha256] of packageBindings) {
    assert.match(dockerfile, new RegExp(`ARG ${name}=${sha256}`));
  }
  assertImmutablePackageBindings(immutableInputs);
  assert.match(immutableInputs, new RegExp(`version: ${version.replaceAll('.', '\\.')}`));
});

test('rejects immutable Chromium inputs whose architecture hashes are swapped', () => {
  const amd64Hash = packageBindings[0][2];
  const arm64Hash = packageBindings[1][2];
  const swapped = immutableInputs
    .replace(amd64Hash, '__CHROMIUM_SHA256_SWAP__')
    .replace(arm64Hash, amd64Hash)
    .replace('__CHROMIUM_SHA256_SWAP__', arm64Hash);

  assert.throws(
    () => assertImmutablePackageBindings(swapped),
    /amd64-chromium-package-sha256/,
  );
});

test('publishes Chromium 153 as the product and runtime fact', () => {
  assert.equal(facts.browser.chromium.version, '153.0.8010.52');
  for (const path of [
    'README.md',
    'docs/architecture.md',
    'docs/dockerhub-description.md',
    'config/claude-memory-full.md',
    'config/claude-memory-slim.md',
    'THIRD-PARTY-NOTICES',
  ]) {
    assert.match(readFileSync(path, 'utf8'), /153\.0\.8010\.52/, path);
  }
});

test('retires the fixed Chromium Critical exceptions and their bound evidence records', () => {
  const exceptions = ledger.reviews.filter((review) =>
    review.owner === 'Debian Bookworm Chromium' && review.disposition === 'critical_exception');
  assert.deepEqual(exceptions, []);

  for (const suffix of ['', '-full-amd64', '-full-arm64', '-slim-amd64', '-slim-arm64']) {
    const path = `security/critical-exception-authority-evidence${suffix}.json`;
    const evidence = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual(evidence.records, [], path);
  }
});

test('does not carry retired Chromium reviews into the Chromium 153 release', () => {
  const staleReviews = ledger.reviews.filter((review) =>
    review.component.names.some((name) => chromiumPackageNames.has(name)) &&
    review.component.versions.some((reviewVersion) => retiredChromiumVersions.has(reviewVersion)));
  assert.deepEqual(staleReviews, []);
});
