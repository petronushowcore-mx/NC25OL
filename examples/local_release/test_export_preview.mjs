/** Bounded exporter checks; all generated data stays in explicit caller scratch. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, isAbsolute, join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath, pathToFileURL} from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const candidateArg = args.indexOf('--candidate');
assert(candidateArg >= 0 && isAbsolute(args[candidateArg + 1] || ''), 'Pass --candidate <absolute OTCS directory>');
const candidate = realpathSync(args[candidateArg + 1]);
assert(process.env.OTCS_TEST_SCRATCH && isAbsolute(process.env.OTCS_TEST_SCRATCH), 'Set explicit OTCS_TEST_SCRATCH');
const root = mkdtempSync(join(realpathSync(process.env.OTCS_TEST_SCRATCH), 'preview-export-check-'));
process.env.OTCS_TEST_SCRATCH = root;
const sourcePath = process.env.PREVIEW_EXPORT_MODULE || join(HERE, 'export_preview.mjs');
const markers = ['PUBLIC_ONLY', 'TERMS_EXACT', 'BAD_TERM_REFUSAL', 'PRE_ADMISSION', 'SCRATCH_REQUIRED', 'SCRATCH_BOUNDARY', 'OUTPUT_BOUNDARY', 'NO_OVERWRITE'];
const sameError = code => error => error.message === code;
const sha = value => createHash('sha256').update(value).digest('hex');

if (args.includes('--mutations')) {
  const original = readFileSync(sourcePath, 'utf8');
  const mutations = [
    ['PUBLIC_ONLY', 'public_fields: {...verified.projections.facts.value.values, ...verified.projections.statement.value.values},', 'public_fields: structuredClone(source),'],
    ['TERMS_EXACT', 'reference: structuredClone(policy[kind]),', "reference: {...structuredClone(policy[kind]), sha256: '0'.repeat(64)},"],
    ['BAD_TERM_REFUSAL', 'if (!verified.ok) throw new Error(verified.code);', 'if (!verified.ok) return {};'],
    ['PRE_ADMISSION', 'admitted: false,', 'admitted: true,'],
    ['SCRATCH_REQUIRED', 'const scratchPath = process.env.OTCS_TEST_SCRATCH;', 'const scratchPath = process.env.OTCS_TEST_SCRATCH || process.env.PREVIEW_MUTATION_SCRATCH;'],
    ['SCRATCH_BOUNDARY', 'if (contained(candidate, path)) throw new Error(code);', '// Lost candidate containment guard.'],
    ['SCRATCH_BOUNDARY', "if (existsSync(join(at, 'PACKAGE-MANIFEST.json'))) throw new Error(code);", '// Lost ancestor package guard.'],
    ['OUTPUT_BOUNDARY', "outsidePackage(parent, candidate, 'PREVIEW_OUTPUT_INSIDE_PACKAGE');", '// Lost output containment check.'],
    ['NO_OVERWRITE', "flag: 'wx'", "flag: 'w'"],
  ];
  assert.deepEqual([...new Set(mutations.map(row => row[0]))], markers);
  const run = module => spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--candidate', candidate], {
    encoding: 'utf8', timeout: 60000,
    env: {...process.env, PREVIEW_EXPORT_MODULE: module},
  });
  const baseline = run(sourcePath);
  writeFileSync(join(root, 'baseline.log'), baseline.stdout + baseline.stderr);
  assert.equal(baseline.status, 0, baseline.stdout + baseline.stderr);
  assert.deepEqual([...baseline.stdout.matchAll(/^PASS (\S+)$/gm)].map(match => match[1]), markers);
  const results = [];
  for (const [index, [marker, from, to]] of mutations.entries()) {
    assert.equal(original.split(from).length, 2, 'Mutation must hit one real source site: ' + marker);
    const path = join(root, 'mutation-' + index + '.mjs');
    writeFileSync(path, original.replace(from, to));
    const result = run(path);
    writeFileSync(join(root, 'mutation-' + index + '.log'), result.stdout + result.stderr);
    assert.equal(result.status, 1, marker + ': must fail by named check\n' + result.stdout + result.stderr);
    assert.deepEqual([...result.stdout.matchAll(/^FAIL (\S+)$/gm)].map(match => match[1]), [marker], marker + ': wrong first failure');
    results.push({mutation: index, first_failure: marker});
    console.log('BITES_FIRST ' + marker);
  }
  writeFileSync(join(root, 'results.json'), JSON.stringify({markers, results, scope: 'synthetic exporter only'}, null, 2) + '\n');
  console.log('MUTATIONS ' + results.length + '/' + mutations.length + '; evidence ' + root);
} else {
  const {buildPreview, exportPreview} = await import(pathToFileURL(sourcePath).href);
  let preview;
  const fakeCandidate = join(root, 'fake-candidate');
  const fakePackage = join(root, 'fake-package');
  mkdirSync(fakeCandidate);
  mkdirSync(fakePackage);
  writeFileSync(join(fakePackage, 'PACKAGE-MANIFEST.json'), '{}\n');
  const checks = [
    ['PUBLIC_ONLY', async () => {
      let sawPrivateCanary = false;
      preview = await buildPreview(candidate, source => {
        sawPrivateCanary = source.project.maintainers[0].name === 'SYNTHETIC_PRIVATE_SOURCE_ONLY_EXPORT_937';
        assert.equal(source.record.public_entry_statement.claims[0], 'Synthetic public statement for a local integration example.');
      });
      assert(sawPrivateCanary, 'The fixture really contains excluded source material');
      assert.deepEqual(Object.keys(preview).sort(), ['format', 'synthetic', 'admitted', 'project_id', 'public_fields', 'terms'].sort());
      assert.equal(typeof preview.project_id, 'string');
      assert(preview.project_id.length > 0);
      assert.equal(preview.public_fields['/project/id'], preview.project_id);
      assert.deepEqual(preview.public_fields['/record/public_entry_statement/claims'], ['Synthetic public statement for a local integration example.']);
      assert(!JSON.stringify(preview).includes('SYNTHETIC_PRIVATE_SOURCE_ONLY_EXPORT_937'));
      assert(!Object.hasOwn(preview.public_fields, '/project/maintainers'));
      assert(!Object.hasOwn(preview.public_fields, '/consent'));
      assert(!Object.hasOwn(preview, 'source'));
    }],
    ['TERMS_EXACT', async () => {
      // Independent fixture manifest/member bytes, not the exporter's resolver.
      const {fixture} = await import(pathToFileURL(join(candidate, 'envelope-cases.mjs')).href);
      const input = fixture({storage: 'reference_only'}).input.submission;
      const bindings = JSON.parse(input.bundleInput.manifestBytes).bindings;
      const source = JSON.parse(input.sourceBytes);
      const versions = [source.record.registry_grants[0].version, source.consent.terms_version, source.consent.platform_disclosure_version];
      assert.deepEqual(preview.terms.map(term => term.kind), ['grant_terms', 'consent_terms', 'platform_disclosure']);
      for (const [index, term] of preview.terms.entries()) {
        assert.deepEqual(Object.keys(term).sort(), ['kind', 'reference', 'version', 'text'].sort());
        const binding = bindings.find(item => item.kind === term.kind);
        assert.deepEqual(term.reference, {id: binding.id, sha256: binding.sha256});
        assert.equal(term.text, input.bundleInput.members.get(binding.member_path).toString('utf8'));
        assert.equal(sha(term.text), term.reference.sha256);
        assert.equal(term.version, versions[index]);
        assert(term.text.startsWith('Synthetic '), 'Fixture terms must remain explicitly synthetic');
      }
    }],
    ['BAD_TERM_REFUSAL', async () => {
      await assert.rejects(buildPreview(candidate, source => {source.consent.terms_sha256 = '0'.repeat(64);}), sameError('SUBMISSION_AUTHORITY'));
    }],
    ['PRE_ADMISSION', async () => {
      assert.equal(preview.format, 'otcs-registration-preview/v1');
      assert.equal(preview.synthetic, true);
      assert.equal(preview.admitted, false);
    }],
    ['SCRATCH_REQUIRED', async () => {
      const saved = process.env.OTCS_TEST_SCRATCH;
      process.env.PREVIEW_MUTATION_SCRATCH = root;
      delete process.env.OTCS_TEST_SCRATCH;
      try { await assert.rejects(buildPreview(candidate), sameError('PREVIEW_SCRATCH_REQUIRED')); }
      finally { process.env.OTCS_TEST_SCRATCH = saved; delete process.env.PREVIEW_MUTATION_SCRATCH; }
      await assert.rejects(buildPreview('relative-candidate'), sameError('PREVIEW_CANDIDATE_ABSOLUTE_DIRECTORY'));
    }],
    ['SCRATCH_BOUNDARY', async () => {
      const saved = process.env.OTCS_TEST_SCRATCH;
      try {
        process.env.OTCS_TEST_SCRATCH = fakeCandidate;
        await assert.rejects(buildPreview(fakeCandidate), sameError('PREVIEW_SCRATCH_INSIDE_PACKAGE'));
        process.env.OTCS_TEST_SCRATCH = fakePackage;
        await assert.rejects(buildPreview(candidate), sameError('PREVIEW_SCRATCH_INSIDE_PACKAGE'));
      } finally { process.env.OTCS_TEST_SCRATCH = saved; }
    }],
    ['OUTPUT_BOUNDARY', async () => {
      const inCandidate = join(fakeCandidate, 'preview.json');
      const inPackage = join(fakePackage, 'preview.json');
      await assert.rejects(exportPreview(fakeCandidate, inCandidate), sameError('PREVIEW_OUTPUT_INSIDE_PACKAGE'));
      await assert.rejects(exportPreview(candidate, inPackage), sameError('PREVIEW_OUTPUT_INSIDE_PACKAGE'));
      await assert.rejects(exportPreview(candidate, 'relative.json'), sameError('PREVIEW_OUTPUT_ABSOLUTE'));
      assert(!existsSync(inCandidate));
      assert(!existsSync(inPackage));
    }],
    ['NO_OVERWRITE', async () => {
      const output = join(root, 'new-preview.json');
      assert.equal(await exportPreview(candidate, output), output);
      assert.deepEqual(JSON.parse(readFileSync(output, 'utf8')), preview);
      const protectedPath = join(root, 'already-there.json');
      const sentinel = '{"owned":"another artifact"}\n';
      writeFileSync(protectedPath, sentinel);
      await assert.rejects(exportPreview(candidate, protectedPath), error => error.code === 'EEXIST');
      assert.equal(readFileSync(protectedPath, 'utf8'), sentinel);
    }],
  ];
  assert.deepEqual(checks.map(row => row[0]), markers);
  for (const [name, check] of checks) {
    try { await check(); console.log('PASS ' + name); }
    catch (error) { console.log('FAIL ' + name); console.error(error.stack); process.exit(1); }
  }
  console.log('CHECKS ' + checks.length + '/' + markers.length + '; evidence ' + root);
}
