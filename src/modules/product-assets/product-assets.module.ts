import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ProductAssetsService } from './product-assets.service';

@Module({
  imports: [PrismaModule],
  providers: [ProductAssetsService],
  exports: [ProductAssetsService],
})
export class ProductAssetsModule {}
