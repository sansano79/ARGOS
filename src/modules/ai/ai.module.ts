import { Module } from '@nestjs/common';
import { AiService } from './ai.service';
import { AiController } from './ai.controller';
import { PrismaModule } from '../../prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
    imports: [
        PrismaModule,
        ConfigModule,
        HttpModule,
        ThrottlerModule.forRoot([{
            name: 'ai-chat',
            ttl: 60_000,
            limit: parseInt(process.env.AI_CHAT_RATE_LIMIT_PER_MIN || '10', 10),
        }]),
    ],
    providers: [AiService],
    controllers: [AiController],
    exports: [AiService],
})
export class AiModule { }
