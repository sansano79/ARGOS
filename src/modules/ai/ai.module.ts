import { Module } from '@nestjs/common';
import { AiService } from './ai.service';
import { AiController } from './ai.controller';
import { PrismaModule } from '../../prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';

@Module({
    imports: [PrismaModule, ConfigModule, HttpModule],
    providers: [AiService],
    controllers: [AiController],
    exports: [AiService],
})
export class AiModule { }
