jest.mock('nodemailer', () => ({
  createTransport: jest.fn(),
}));

import * as nodemailer from 'nodemailer';
import { NotificationService } from './notification.service';

describe('NotificationService SMTP draft testing', () => {
  it('sends a test email with an unsaved SMTP draft', async () => {
    const sendMail = jest.fn().mockResolvedValue({ messageId: 'draft-message-id' });
    (nodemailer.createTransport as jest.Mock).mockReturnValue({ sendMail });
    const prisma = {
      apiConfiguration: { findFirst: jest.fn().mockResolvedValue(null) },
    };
    const service = new NotificationService(prisma as any, {} as any);
    jest.spyOn(service as any, 'logNotification').mockResolvedValue(undefined);

    const result = await (service as any).sendTestEmail('security@example.test', {
      host: 'smtp.example.test',
      port: 587,
      user: 'argos@example.test',
      pass: 'draft-password',
      secure: false,
      from: 'argos@example.test',
    });

    expect(result).toEqual({ success: true, messageId: 'draft-message-id' });
    expect(sendMail).toHaveBeenCalledWith(expect.objectContaining({
      from: 'argos@example.test',
      to: 'security@example.test',
    }));
  });
});
