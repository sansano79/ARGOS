SET @db := DATABASE();

CREATE TABLE IF NOT EXISTS `api_keys` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(191) NOT NULL,
  `key_hash` VARCHAR(191) NOT NULL,
  `key_prefix` VARCHAR(12) NOT NULL,
  `user_id` INTEGER NOT NULL,
  `scopes` TEXT NOT NULL,
  `is_active` BOOLEAN NOT NULL DEFAULT true,
  `expires_at` DATETIME(3) NULL,
  `last_used_at` DATETIME(3) NULL,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

SET @idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema=@db AND table_name='api_keys' AND index_name='api_keys_key_hash_key'
);
SET @sql := IF(@idx=0, "CREATE UNIQUE INDEX `api_keys_key_hash_key` ON `api_keys`(`key_hash`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema=@db AND table_name='api_keys' AND index_name='api_keys_key_prefix_idx'
);
SET @sql := IF(@idx=0, "CREATE INDEX `api_keys_key_prefix_idx` ON `api_keys`(`key_prefix`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema=@db AND table_name='api_keys' AND index_name='api_keys_user_id_idx'
);
SET @sql := IF(@idx=0, "CREATE INDEX `api_keys_user_id_idx` ON `api_keys`(`user_id`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema=@db AND table_name='api_keys' AND index_name='api_keys_is_active_idx'
);
SET @sql := IF(@idx=0, "CREATE INDEX `api_keys_is_active_idx` ON `api_keys`(`is_active`)", "SELECT 1");
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @fk := (
  SELECT COUNT(*)
  FROM information_schema.table_constraints
  WHERE constraint_schema=@db
    AND table_name='api_keys'
    AND constraint_name='api_keys_user_id_fkey'
    AND constraint_type='FOREIGN KEY'
);
SET @sql := IF(
  @fk=0,
  "ALTER TABLE `api_keys` ADD CONSTRAINT `api_keys_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE",
  "SELECT 1"
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
