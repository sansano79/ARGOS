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
  assert.match(template, /\{\{\s*kpiSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*findingSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*topRiskSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*whyReceivedSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*mitigationSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*technicalSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*closingSectionHtml\s*\}\}/);
  assert.match(template, /\{\{\s*greetingHtml\s*\}\}/);
  assert.match(template, /\{\{\s*introHtml\s*\}\}/);
  assert.match(template, /\{\{\s*generatedAtLine\s*\}\}/);
});

test('intelligent email context rebuilds the high-value analytical sections', () => {
  const source = fs.readFileSync(smartServicePath, 'utf8');
  assert.match(source, /Top riesgo \(Top 3\)/);
  assert.match(source, /Qué hacer hoy \/ Hoja de ruta de mitigación/);
  assert.match(source, /Base técnica analizada \(compacta\)/);
  assert.match(source, /Por qué recibes esta alerta/);
  assert.match(source, /buildIntelligentFindingSectionHtml/);
  assert.match(source, /buildIntelligentMitigationSectionHtml/);
  assert.match(source, /buildIntelligentTechnicalSectionHtml/);
});
