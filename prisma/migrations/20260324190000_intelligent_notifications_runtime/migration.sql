ALTER TABLE `users`
  ADD COLUMN `communication_language` VARCHAR(10) NOT NULL DEFAULT 'es';

ALTER TABLE `notification_policies`
  ADD COLUMN `intelligent_min_relevance_score` DOUBLE NULL,
  ADD COLUMN `intelligent_cooldown_hours` INTEGER NULL,
  ADD COLUMN `intelligent_max_notifications_per_day` INTEGER NULL,
  ADD COLUMN `intelligent_exclusions` TEXT NULL;

CREATE TABLE `intelligent_notification_findings` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `finding_key` VARCHAR(191) NOT NULL,
  `finding_type` VARCHAR(191) NOT NULL,
  `title` VARCHAR(191) NOT NULL,
  `summary` TEXT NOT NULL,
  `confidence` DOUBLE NOT NULL,
  `relevance_score` DOUBLE NOT NULL,
  `risk_score` DOUBLE NULL,
  `detected_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `window_start` DATETIME(3) NOT NULL,
  `window_end` DATETIME(3) NOT NULL,
  `context_start` DATETIME(3) NOT NULL,
  `context_end` DATETIME(3) NOT NULL,
  `affected_vulnerability_ids` LONGTEXT NOT NULL,
  `affected_manufacturers` TEXT NULL,
  `affected_products` LONGTEXT NULL,
  `recommended_actions` LONGTEXT NULL,
  `raw_model_output` LONGTEXT NULL,
  `normalized_model_output` LONGTEXT NULL,
  `status` VARCHAR(191) NOT NULL DEFAULT 'detected',
  `is_test` BOOLEAN NOT NULL DEFAULT false,
  `job_run_id` INTEGER NULL,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,

  UNIQUE INDEX `intelligent_notification_findings_finding_key_key`(`finding_key`),
  INDEX `intelligent_notification_findings_finding_type_idx`(`finding_type`),
  INDEX `intelligent_notification_findings_status_idx`(`status`),
  INDEX `intelligent_notification_findings_is_test_idx`(`is_test`),
  INDEX `intelligent_notification_findings_detected_at_idx`(`detected_at` DESC),
  INDEX `intelligent_notification_findings_job_run_id_idx`(`job_run_id`),
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `intelligent_notification_subscriber_matches` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `finding_id` INTEGER NOT NULL,
  `subscriber_user_id` INTEGER NOT NULL,
  `match_level` VARCHAR(191) NOT NULL,
  `match_score` DOUBLE NOT NULL,
  `delivery_score` DOUBLE NOT NULL,
  `should_notify` BOOLEAN NOT NULL DEFAULT false,
  `suppression_reason` TEXT NULL,
  `decision_reason` TEXT NULL,
  `matching_signals` LONGTEXT NULL,
  `cooldown_until` DATETIME(3) NULL,
  `sent_at` DATETIME(3) NULL,
  `notification_log_id` INTEGER NULL,
  `is_test` BOOLEAN NOT NULL DEFAULT false,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,

  UNIQUE INDEX `insm_finding_subscriber_key`(`finding_id`, `subscriber_user_id`),
  INDEX `intelligent_notification_subscriber_matches_subscriber_user_id_idx`(`subscriber_user_id`),
  INDEX `intelligent_notification_subscriber_matches_should_notify_idx`(`should_notify`),
  INDEX `intelligent_notification_subscriber_matches_is_test_idx`(`is_test`),
  INDEX `intelligent_notification_subscriber_matches_sent_at_idx`(`sent_at` DESC),
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `intelligent_notification_test_runs` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `subscriber_user_id` INTEGER NULL,
  `mode` VARCHAR(191) NOT NULL,
  `status` VARCHAR(191) NOT NULL DEFAULT 'running',
  `target_email` VARCHAR(191) NULL,
  `communication_language` VARCHAR(10) NOT NULL DEFAULT 'es',
  `primary_window_hours` INTEGER NOT NULL DEFAULT 24,
  `recent_context_days` INTEGER NOT NULL DEFAULT 7,
  `historical_context_days` INTEGER NOT NULL DEFAULT 60,
  `use_recent_real_data` BOOLEAN NOT NULL DEFAULT true,
  `input_options` LONGTEXT NULL,
  `findings_detected` INTEGER NOT NULL DEFAULT 0,
  `notifications_planned` INTEGER NOT NULL DEFAULT 0,
  `notifications_sent` INTEGER NOT NULL DEFAULT 0,
  `notifications_suppressed` INTEGER NOT NULL DEFAULT 0,
  `rendered_subject` TEXT NULL,
  `rendered_html` LONGTEXT NULL,
  `result_summary` LONGTEXT NULL,
  `quality_assessment` LONGTEXT NULL,
  `error_message` TEXT NULL,
  `started_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `completed_at` DATETIME(3) NULL,
  `duration_ms` INTEGER NULL,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,

  INDEX `intelligent_notification_test_runs_subscriber_user_id_idx`(`subscriber_user_id`),
  INDEX `intelligent_notification_test_runs_mode_idx`(`mode`),
  INDEX `intelligent_notification_test_runs_status_idx`(`status`),
  INDEX `intelligent_notification_test_runs_started_at_idx`(`started_at` DESC),
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `intelligent_notification_subscriber_matches`
  ADD CONSTRAINT `intelligent_notification_subscriber_matches_finding_id_fkey`
    FOREIGN KEY (`finding_id`) REFERENCES `intelligent_notification_findings`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `intelligent_notification_subscriber_matches_subscriber_user_id_fkey`
    FOREIGN KEY (`subscriber_user_id`) REFERENCES `users`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `intelligent_notification_test_runs`
  ADD CONSTRAINT `intelligent_notification_test_runs_subscriber_user_id_fkey`
    FOREIGN KEY (`subscriber_user_id`) REFERENCES `users`(`id`)
    ON DELETE SET NULL ON UPDATE CASCADE;
