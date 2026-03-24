const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const smartTemplatePath = path.join(repoRoot, 'src', 'templates', 'smart-weekly-report.html');
const smartServicePath = path.join(repoRoot, 'src', 'modules', 'smart-notifications', 'smart-notifications.service.ts');

test('intelligent email template keeps the premium detail placeholders', () => {
  const template = fs.readFileSync(smartTemplatePath, 'utf8');
  assert.match(template, /\{\{\s*executiveSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*statsSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*topRiskSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*correlationsSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*roadmapSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*technicalSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*whyReceivedSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*closingSectionHtml\s*\}\}/);
});

test('intelligent email context rebuilds the high-value analytical sections', () => {
  const source = fs.readFileSync(smartServicePath, 'utf8');
  assert.match(source, /Top riesgo real/);
  assert.match(source, /Correlaciones detectadas/);
  assert.match(source, /Hoja de ruta de mitigación/);
  assert.match(source, /Base técnica analizada/);
  assert.match(source, /Por qué recibes esta alerta/);
  assert.match(source, /buildIntelligentCorrelationBlock/);
  assert.match(source, /buildIntelligentRoadmapHtml/);
  assert.match(source, /buildIntelligentTechnicalTable/);
});
