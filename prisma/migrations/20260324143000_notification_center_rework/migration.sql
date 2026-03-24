ALTER TABLE `users`
  ADD COLUMN `can_receive_notifications` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `notifications_paused` BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN `notifications_paused_until` DATETIME(3) NULL,
  ADD COLUMN `last_notification_sent_at` DATETIME(3) NULL;

ALTER TABLE `notification_logs`
  ADD COLUMN `notification_type` VARCHAR(191) NOT NULL DEFAULT 'normal',
  ADD COLUMN `template_key` VARCHAR(191) NULL,
  ADD COLUMN `channel` VARCHAR(191) NOT NULL DEFAULT 'email',
  ADD COLUMN `vulnerability_count` INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN `trigger_reason` VARCHAR(191) NULL,
  ADD COLUMN `error_message` TEXT NULL,
  ADD COLUMN `metadata_json` LONGTEXT NULL;

CREATE INDEX `notification_logs_notification_type_idx` ON `notification_logs`(`notification_type`);
CREATE INDEX `notification_logs_status_idx` ON `notification_logs`(`status`);

ALTER TABLE `notification_policies`
  ADD COLUMN `immediate_enabled` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `immediate_min_severity` VARCHAR(191) NULL,
  ADD COLUMN `immediate_min_cvss` DOUBLE NULL,
  ADD COLUMN `immediate_min_epss` DOUBLE NULL,
  ADD COLUMN `immediate_min_epss_percentile` DOUBLE NULL,
  ADD COLUMN `immediate_kev_only` BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN `immediate_public_exploit_only` BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN `immediate_active_exploitation_only` BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN `immediate_patch_unconfirmed_only` BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN `immediate_only_new_vulnerabilities` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `immediate_on_severity_change` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `immediate_on_exploit_change` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `immediate_on_patch_change` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `immediate_only_subscribed_systems` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `immediate_min_confidence` DOUBLE NULL,
  ADD COLUMN `immediate_min_sources` INTEGER NULL,
  ADD COLUMN `immediate_vendor_filters` TEXT NULL,
  ADD COLUMN `immediate_product_filters` TEXT NULL,
  ADD COLUMN `immediate_category_filters` TEXT NULL,
  ADD COLUMN `immediate_exclusions` TEXT NULL,
  ADD COLUMN `digest_enabled` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `digest_min_severity` VARCHAR(191) NULL,
  ADD COLUMN `digest_min_cvss` DOUBLE NULL,
  ADD COLUMN `digest_min_epss` DOUBLE NULL,
  ADD COLUMN `digest_only_subscribed_systems` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `digest_min_confidence` DOUBLE NULL,
  ADD COLUMN `digest_min_sources` INTEGER NULL,
  ADD COLUMN `digest_vendor_filters` TEXT NULL,
  ADD COLUMN `digest_product_filters` TEXT NULL,
  ADD COLUMN `digest_category_filters` TEXT NULL,
  ADD COLUMN `digest_exclusions` TEXT NULL,
  ADD COLUMN `digest_last_watermark_at` DATETIME(3) NULL,
  ADD COLUMN `intelligent_enabled` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `intelligent_daily_hour` INTEGER NOT NULL DEFAULT 8,
  ADD COLUMN `intelligent_lookback_hours` INTEGER NOT NULL DEFAULT 24,
  ADD COLUMN `intelligent_context_days` INTEGER NOT NULL DEFAULT 7,
  ADD COLUMN `intelligent_min_confidence` DOUBLE NULL,
  ADD COLUMN `intelligent_only_when_finding` BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN `intelligent_scenario_flags` TEXT NULL,
  ADD COLUMN `intelligent_last_watermark_at` DATETIME(3) NULL;

CREATE TABLE `notification_job_runs` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `job_type` VARCHAR(191) NOT NULL,
  `trigger_mode` VARCHAR(191) NOT NULL DEFAULT 'manual',
  `status` VARCHAR(191) NOT NULL DEFAULT 'running',
  `started_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at` DATETIME(3) NULL,
  `watermark_from` DATETIME(3) NULL,
  `watermark_to` DATETIME(3) NULL,
  `notifications_sent` INTEGER NOT NULL DEFAULT 0,
  `notifications_failed` INTEGER NOT NULL DEFAULT 0,
  `vulnerabilities_considered` INTEGER NOT NULL DEFAULT 0,
  `queue_pending` INTEGER NOT NULL DEFAULT 0,
  `retry_count` INTEGER NOT NULL DEFAULT 0,
  `error_message` TEXT NULL,
  `details` LONGTEXT NULL,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,

  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE INDEX `notification_job_runs_job_type_idx` ON `notification_job_runs`(`job_type`);
CREATE INDEX `notification_job_runs_status_idx` ON `notification_job_runs`(`status`);
CREATE INDEX `notification_job_runs_started_at_idx` ON `notification_job_runs`(`started_at` DESC);
