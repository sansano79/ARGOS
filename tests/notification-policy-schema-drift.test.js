const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const schemaPath = path.join(repoRoot, 'prisma', 'schema.prisma');
const migrationPath = path.join(
  repoRoot,
  'prisma',
  'migrations',
  '20260324143000_notification_center_rework',
  'migration.sql',
);

test('notification policy exclusions stay mapped to snake_case DB columns', () => {
  const schema = fs.readFileSync(schemaPath, 'utf8');
  assert.match(schema, /immediateExclusions\s+String\?\s+@map\("immediate_exclusions"\)\s+@db\.Text/);
  assert.match(schema, /digestExclusions\s+String\?\s+@map\("digest_exclusions"\)\s+@db\.Text/);
});

test('notification center migration created the exclusion columns in snake_case', () => {
  const migration = fs.readFileSync(migrationPath, 'utf8');
  assert.match(migration, /`immediate_exclusions`\s+TEXT\s+NULL/);
  assert.match(migration, /`digest_exclusions`\s+TEXT\s+NULL/);
});
