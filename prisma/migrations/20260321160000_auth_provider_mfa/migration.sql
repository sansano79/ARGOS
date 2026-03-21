-- Deploy-safe migration for existing databases possibly created via db push.
-- Uses information_schema checks to avoid failing when columns/indexes already exist.

SET @db := DATABASE();

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='auth_provider');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `auth_provider` VARCHAR(32) NOT NULL DEFAULT 'LOCAL'", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='external_id');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `external_id` VARCHAR(191) NULL", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='mfa_enabled');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `mfa_enabled` BOOLEAN NOT NULL DEFAULT 0", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='mfa_secret_enc');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `mfa_secret_enc` TEXT NULL", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='mfa_secret_iv');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `mfa_secret_iv` VARCHAR(191) NULL", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='mfa_secret_tag');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `mfa_secret_tag` VARCHAR(191) NULL", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=@db AND table_name='users' AND column_name='last_login_at');
SET @sql := IF(@col=0, "ALTER TABLE `users` ADD COLUMN `last_login_at` DATETIME(3) NULL", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema=@db AND table_name='users'
    AND non_unique=0
    AND column_name='external_id'
);
SET @sql := IF(@idx=0, "CREATE UNIQUE INDEX `users_external_id_key` ON `users`(`external_id`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
