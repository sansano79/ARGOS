-- AlterTable
ALTER TABLE `vulnerabilities` ADD COLUMN `is_notificable` BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX `vulnerabilities_is_notificable_idx` ON `vulnerabilities`(`is_notificable`);
