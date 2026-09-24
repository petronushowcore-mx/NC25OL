/** Synthetic, pre-admission projection only. No live consent or adopted policy. */
import {existsSync, realpathSync, statSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, join, relative, resolve, sep} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const PRIVATE_CANARY = 'SYNTHETIC_PRIVATE_SOURCE_ONLY_EXPORT_937';
const PUBLIC_CLAIM = 'Synthetic public statement for a local integration example.';
const TERM_KINDS = ['grant_terms', 'consent_terms', 'platform_disclosure'];

function directory(value, code) {
  if (typeof value !== 'string' || !isAbsolute(value)) throw new Error(code);
  const path = realpathSync(value);
  if (!statSync(path).isDirectory()) throw new Error(code);
  return path;
}

function contained(parent, child) {
  const delta = relative(parent, child);
  return delta === '' || (delta !== '..' && !delta.startsWith('..' + sep) && !isAbsolute(delta));
}

function outsidePackage(path, candidate, code) {
  if (contained(candidate, path)) throw new Error(code);
  for (let at = path; ; at = dirname(at)) {
    if (existsSync(join(at, 'PACKAGE-MANIFEST.json'))) throw new Error(code);
    if (dirname(at) === at) break;
  }
}

export async function buildPreview(candidatePath, change = () => {}) {
  const candidate = directory(candidatePath, 'PREVIEW_CANDIDATE_ABSOLUTE_DIRECTORY');
  const scratchPath = process.env.OTCS_TEST_SCRATCH;
  const scratch = directory(scratchPath, 'PREVIEW_SCRATCH_REQUIRED');
  outsidePackage(scratch, candidate, 'PREVIEW_SCRATCH_INSIDE_PACKAGE');
  const load = name => import(pathToFileURL(join(candidate, name)).href);
  const [{fixture}, {verifyOwnerSubmission}, {verifyBundle}] = await Promise.all([
    load('envelope-cases.mjs'), load('submission-evidence.mjs'), load('bindings.mjs'),
  ]);
  const input = fixture({storage: 'reference_only', source(source) {
    source.project.maintainers[0].name = PRIVATE_CANARY;
    source.record.public_entry_statement.claims = [PUBLIC_CLAIM];
    source.record.public_entry_statement.non_claims = ['Synthetic example only; not a live participant.'];
    change(source);
  }}).input.submission;
  const verified = verifyOwnerSubmission(input);
  if (!verified.ok) throw new Error(verified.code);
  const bundle = verifyBundle(input.bundleInput);
  if (!bundle.ok) throw new Error(bundle.code);
  const bound = (kind, reference) => {
    const result = bundle.resolve(kind, reference);
    if (!result.ok) throw new Error(result.code);
    return result.value;
  };
  const source = JSON.parse(input.sourceBytes);
  const policy = bound('authority_policy', verified.authority.policy);
  const versions = {
    grant_terms: source.record.registry_grants[0].version,
    consent_terms: source.consent.terms_version,
    platform_disclosure: source.consent.platform_disclosure_version,
  };
  return {
    format: 'otcs-registration-preview/v1',
    synthetic: true,
    admitted: false,
    project_id: verified.project_id,
    public_fields: {...verified.projections.facts.value.values, ...verified.projections.statement.value.values},
    terms: TERM_KINDS.map(kind => ({
      kind,
      reference: structuredClone(policy[kind]),
      version: versions[kind],
      text: bound(kind, policy[kind]).text,
    })),
  };
}

export async function exportPreview(candidatePath, outputPath) {
  const candidate = directory(candidatePath, 'PREVIEW_CANDIDATE_ABSOLUTE_DIRECTORY');
  if (typeof outputPath !== 'string' || !isAbsolute(outputPath)) throw new Error('PREVIEW_OUTPUT_ABSOLUTE');
  const parent = directory(dirname(outputPath), 'PREVIEW_OUTPUT_PARENT');
  outsidePackage(parent, candidate, 'PREVIEW_OUTPUT_INSIDE_PACKAGE');
  const target = join(parent, basename(outputPath));
  const preview = await buildPreview(candidate);
  writeFileSync(target, JSON.stringify(preview, null, 2) + '\n', {encoding: 'utf8', flag: 'wx'});
  return target;
}

async function main(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--candidate', '--output'].includes(args[i]) || !args[i + 1] || Object.hasOwn(options, args[i])) {
      throw new Error('Usage: node export_preview.mjs --candidate <absolute directory> --output <new absolute JSON path>');
    }
    options[args[i]] = args[i + 1];
  }
  if (!options['--candidate'] || !options['--output']) throw new Error('PREVIEW_ARGUMENTS_REQUIRED');
  const output = await exportPreview(options['--candidate'], options['--output']);
  console.log('PREVIEW_WRITTEN ' + output);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await main(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
