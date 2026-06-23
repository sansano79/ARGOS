-- Fase 1A: Modelos aditivos de equipos suscriptores
-- No se modifica ni elimina ninguna tabla legacy.
-- Tablas nuevas: subscriber_teams, team_members, notification_recipients,
--                team_subscriptions, team_systems

CREATE TABLE `subscriber_teams` (
  `id`          INT NOT NULL AUTO_INCREMENT,
  `name`        VARCHAR(191) NOT NULL,
  `code`        VARCHAR(191) NOT NULL,
  `description` TEXT NULL,
  `is_active`   TINYINT(1) NOT NULL DEFAULT 1,
  `created_at`  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3) NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE KEY `subscriber_teams_code_key` (`code`),
  INDEX `subscriber_teams_name_idx` (`name`),
  INDEX `subscriber_teams_is_active_idx` (`is_active`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `team_members` (
  `id`         INT NOT NULL AUTO_INCREMENT,
  `team_id`    INT NOT NULL,
  `user_id`    INT NOT NULL,
  `role`       VARCHAR(191) NOT NULL,
  `is_active`  TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE KEY `team_members_team_id_user_id_key` (`team_id`, `user_id`),
  INDEX `team_members_user_id_idx` (`user_id`),
  INDEX `team_members_team_id_role_idx` (`team_id`, `role`),
  CONSTRAINT `team_members_team_id_fkey`
    FOREIGN KEY (`team_id`) REFERENCES `subscriber_teams` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `team_members_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `notification_recipients` (
  `id`          INT NOT NULL AUTO_INCREMENT,
  `team_id`     INT NOT NULL,
  `name`        VARCHAR(191) NULL,
  `email`       VARCHAR(191) NOT NULL,
  `type`        VARCHAR(191) NOT NULL DEFAULT 'MAILBOX',
  `is_active`   TINYINT(1) NOT NULL DEFAULT 1,
  `verified_at` DATETIME(3) NULL,
  `language`    VARCHAR(191) NOT NULL DEFAULT 'es',
  `timezone`    VARCHAR(191) NOT NULL DEFAULT 'Europe/Madrid',
  `created_at`  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3) NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE KEY `notif_recipients_team_email_key` (`team_id`, `email`),
  INDEX `notif_recipients_email_idx` (`email`),
  INDEX `notif_recipients_team_active_idx` (`team_id`, `is_active`),
  CONSTRAINT `notif_recipients_team_id_fkey`
    FOREIGN KEY (`team_id`) REFERENCES `subscriber_teams` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `team_subscriptions` (
  `id`         INT NOT NULL AUTO_INCREMENT,
  `team_id`    INT NOT NULL,
  `vendor`     VARCHAR(191) NOT NULL,
  `product`    VARCHAR(191) NOT NULL,
  `versions`   TEXT NULL,
  `is_active`  TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3) NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE KEY `team_subs_team_vendor_product_key` (`team_id`, `vendor`, `product`),
  INDEX `team_subs_vendor_product_idx` (`vendor`, `product`),
  CONSTRAINT `team_subs_team_id_fkey`
    FOREIGN KEY (`team_id`) REFERENCES `subscriber_teams` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `team_systems` (
  `id`           INT NOT NULL AUTO_INCREMENT,
  `team_id`      INT NOT NULL,
  `external_id`  VARCHAR(191) NULL,
  `source`       VARCHAR(191) NOT NULL DEFAULT 'manual',
  `name`         VARCHAR(191) NOT NULL,
  `description`  TEXT NULL,
  `hostname`     VARCHAR(191) NULL,
  `fqdn`         VARCHAR(191) NULL,
  `platform`     VARCHAR(191) NULL,
  `os_version`   VARCHAR(191) NULL,
  `risk_level`   VARCHAR(191) NULL,
  `health_status` VARCHAR(191) NULL,
  `is_selected`  TINYINT(1) NOT NULL DEFAULT 1,
  `is_active`    TINYINT(1) NOT NULL DEFAULT 1,
  `tags`         TEXT NULL,
  `raw_data`     LONGTEXT NULL,
  `created_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`   DATETIME(3) NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE KEY `team_systems_team_external_id_key` (`team_id`, `external_id`),
  INDEX `team_systems_team_id_idx` (`team_id`),
  CONSTRAINT `team_systems_team_id_fkey`
    FOREIGN KEY (`team_id`) REFERENCES `subscriber_teams` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
