const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const aiServicePath = path.join(repoRoot, 'src', 'modules', 'ai', 'ai.service.ts');
const smartServicePath = path.join(repoRoot, 'src', 'modules', 'smart-notifications', 'smart-notifications.service.ts');

test('AI service no longer hardcodes a fragile 30s structured JSON timeout', () => {
  const source = fs.readFileSync(aiServicePath, 'utf8');
  assert.doesNotMatch(source, /private static readonly AI_TIMEOUT_MS = 30_000/);
  assert.match(source, /resolveTimeoutMs\(requestedTimeoutMs\?: number\)/);
  assert.match(source, /type AiRequestOptions = \{[\s\S]*timeoutMs\?: number;[\s\S]*\};/);
  assert.match(source, /async chatStructuredJson\(\s*messages: any\[\],\s*options\?: AiRequestOptions,/);
  assert.match(source, /const base = Number\.isFinite\(configured\) && configured > 0 \? configured : 90000;/);
  assert.match(source, /throw new InternalServerErrorException\(`AI structured JSON request failed: \$\{this\.describeAiError\(error, timeoutMs\)\}`\);/);
});

test('smart notification job wraps AI calls with retry and extended timeout', () => {
  const source = fs.readFileSync(smartServicePath, 'utf8');
  assert.match(source, /const maxAttempts = 2;/);
  assert.match(source, /this\.aiService\.chatStructuredJson\(messages, \{ model, timeoutMs: 90000 \}\)/);
  assert.match(source, /Intelligent AI attempt \$\{attempt\}\/\$\{maxAttempts\} failed/);
  assert.match(source, /AI cluster evaluation fallback for \$\{cluster\.key\}:/);
  assert.match(source, /return defaultFinding;/);
});
