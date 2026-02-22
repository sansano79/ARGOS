import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PasswordResetService } from './password-reset.service';
import { PasswordResetController } from './password-reset.controller';
import { NotificationModule } from '../notification/notification.module';

@Module({
    imports: [ConfigModule, NotificationModule],
    providers: [PasswordResetService],
    controllers: [PasswordResetController],
    exports: [PasswordResetService],
})
export class PasswordResetModule { }
