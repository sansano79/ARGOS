import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ProductAssetsModule } from '../product-assets/product-assets.module';
import { DependencyEvidenceImportsService } from './dependency-evidence-imports.service';

@Module({
  imports: [PrismaModule, ProductAssetsModule],
  providers: [DependencyEvidenceImportsService],
  exports: [DependencyEvidenceImportsService],
})
export class DependencyEvidenceImportsModule {}
