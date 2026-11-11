import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const readJson = (file) => JSON.parse(readFileSync(join(root, file), 'utf8'));
const exists = (file) => existsSync(join(root, file));
const problems = [];

const pkg = readJson('package.json');
const plugin = readJson('plugin.json');
const dshPlugin = readJson('dsh.plugin.json');

if (pkg.private === true) problems.push('package.json: private must be removed or false');
if (!pkg.name || pkg.name.startsWith('@local/')) problems.push('package.json: use a public package name');
if (!pkg.version || pkg.version !== plugin.version || pkg.version !== dshPlugin.version) {
  problems.push('package.json, plugin.json, and dsh.plugin.json versions must match');
}
if (!pkg.author) problems.push('package.json: author is required');
if (!pkg.license) problems.push('package.json: license is required');
if (!pkg.engines?.dsh) problems.push('package.json: engines.dsh is required');
if (!pkg.dsh?.bundle?.patch) problems.push('package.json: dsh.bundle.patch is required');
if (pkg.dsh?.client?.platform !== 'web') problems.push('package.json: dsh.client.platform must be web');
if (pkg.exports?.['./client'] !== './client.js') problems.push('package.json: exports["./client"] must point to ./client.js');
if (exists('client.js')) {
  const client = readFileSync(join(root, 'client.js'), 'utf8');
  if (!client.includes(`id: '${pkg.name}'`) && !client.includes(`id: "${pkg.name}"`)) {
    problems.push(`client.js: __ModuleLoader__ id must equal package name "${pkg.name}"`);
  }
}

for (const file of [
  'LICENSE',
  'README.md',
  'PUBLISH.md',
  'index.js',
  'client.js',
  'lib/vault.js',
  'cordis.patch.yml',
  'icon.svg',
  'locale/en.json',
  'locale/zh.json',
  'plugin.json',
  'dsh.plugin.json',
]) {
  if (!exists(file)) problems.push(`missing file: ${file}`);
}

for (const field of ['id', 'name', 'version', 'description', 'author', 'platform', 'harnessVersion', 'entry', 'permissions', 'tags']) {
  if (plugin[field] === undefined || plugin[field] === '') problems.push(`plugin.json: ${field} is required`);
}
if (plugin.name !== pkg.name) problems.push('plugin.json: name must match package.json name');
if (dshPlugin.name !== pkg.name) problems.push('dsh.plugin.json: name must match package.json name');
if (plugin.author !== pkg.author) problems.push('plugin.json: author must match package.json author');
if (plugin.platform !== 'desktop-exe') problems.push('plugin.json: platform should be desktop-exe for this Windows DPAPI build');
if (!Array.isArray(plugin.permissions) || plugin.permissions.length === 0) problems.push('plugin.json: permissions must be a non-empty array');
if (!Array.isArray(plugin.tags) || !plugin.tags.includes('dsh-plugin')) problems.push('plugin.json: tags must include dsh-plugin');

if (exists('icon.svg')) {
  const size = statSync(join(root, 'icon.svg')).size;
  if (size > 256 * 1024) problems.push('icon.svg: must be at most 256 KiB');
}

for (const locale of ['en', 'zh']) {
  const file = `locale/${locale}.json`;
  if (!exists(file)) continue;
  const data = readJson(file);
  if (!data.meta?.title || !data.meta?.description) {
    problems.push(`${file}: meta.title and meta.description are required`);
  }
}

if (problems.length > 0) {
  console.error('Store readiness failed:');
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}

console.log(`Store readiness OK: ${pkg.name}@${pkg.version}`);
console.log(`Author: ${pkg.author}`);
console.log(`License: ${pkg.license}`);
console.log(`Platform: ${plugin.platform}; DSH: ${plugin.harnessVersion}`);
console.log('Next: npm run pack:store');
