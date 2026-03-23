-- Add 3-level notification configuration to NotificationPolicy
ALTER TABLE `notification_policies`
  ADD COLUMN `periodic_enabled` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `periodic_threshold_cvss` DOUBLE NOT NULL DEFAULT 7.0,
  ADD COLUMN `periodic_interval_hours` INT NOT NULL DEFAULT 12,
  ADD COLUMN `periodic_last_sent_at` DATETIME(3) NULL,
  ADD COLUMN `smart_enabled` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `smart_frequency` VARCHAR(191) NOT NULL DEFAULT 'weekly',
  ADD COLUMN `smart_day_of_week` INT NOT NULL DEFAULT 1,
  ADD COLUMN `smart_hour` INT NOT NULL DEFAULT 8;
