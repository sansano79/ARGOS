import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ManufacturersController } from './manufacturers.controller';
import { ManufacturersService } from './manufacturers.service';

@Module({
  imports: [PrismaModule],
  controllers: [ManufacturersController],
  providers: [ManufacturersService],
  exports: [ManufacturersService],
})
export class ManufacturersModule {}

