/**
 * Script para lanzar una recolección manual desde CLI.
 * Uso: npx ts-node scripts/manual-collect.ts
 */
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { VulnerabilityCollectorService } from '../src/modules/vulnerability-collector/vulnerability-collector.service';

async function main() {
  console.log('🚀 Starting manual vulnerability collection...\n');
  
  const app = await NestFactory.createApplicationContext(AppModule);
  const collector = app.get(VulnerabilityCollectorService);

  try {
    const result = await collector.manualCollection();
    console.log('\n✅ Collection completed:');
    console.log(`   CVEs fetched: ${result.fetched}`);
    console.log(`   New CVEs:     ${result.newCves}`);
    console.log(`   Updated:      ${result.updated}`);
  } catch (error) {
    console.error('❌ Collection failed:', error.message);
  } finally {
    await app.close();
  }
}

main();
