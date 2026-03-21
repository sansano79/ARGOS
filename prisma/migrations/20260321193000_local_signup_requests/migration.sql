SET @db := DATABASE();

CREATE TABLE IF NOT EXISTS `local_signup_requests` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `requester_email` VARCHAR(191) NOT NULL,
  `requester_name` VARCHAR(191) NOT NULL,
  `token_hash` VARCHAR(191) NOT NULL,
  `status` VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `expires_at` DATETIME(3) NOT NULL,
  `decided_at` DATETIME(3) NULL,
  `decided_by` VARCHAR(191) NULL,
  `request_ip` VARCHAR(191) NULL,
  `user_agent` TEXT NULL,
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

SET @idx := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=@db AND table_name='local_signup_requests' AND index_name='local_signup_requests_token_hash_idx');
SET @sql := IF(@idx=0, "CREATE INDEX `local_signup_requests_token_hash_idx` ON `local_signup_requests`(`token_hash`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=@db AND table_name='local_signup_requests' AND index_name='local_signup_requests_requester_email_created_at_idx');
SET @sql := IF(@idx=0, "CREATE INDEX `local_signup_requests_requester_email_created_at_idx` ON `local_signup_requests`(`requester_email`, `created_at`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=@db AND table_name='local_signup_requests' AND index_name='local_signup_requests_expires_at_idx');
SET @sql := IF(@idx=0, "CREATE INDEX `local_signup_requests_expires_at_idx` ON `local_signup_requests`(`expires_at`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
