-- ============================================================
-- BASELINE: estado del esquema previo a 20260321160000_auth_provider_mfa
-- Representa el esquema creado originalmente via db push.
--
-- Columnas/tablas EXCLUIDAS intencionalmente (añadidas por migraciones posteriores):
--   users: auth_provider, external_id, mfa_enabled, mfa_secret_enc,
--          mfa_secret_iv, mfa_secret_tag, last_login_at,
--          can_receive_notifications, notifications_paused,
--          notifications_paused_until, last_notification_sent_at,
--          communication_language
--   vulnerabilities: cvss_v40_score, cvss_v40_vector, cvss_v40_severity,
--                    cvss_version, cwe_ids, cwe_names, weakness_category,
--                    is_notificable
--   notification_logs: notification_type, template_key, channel,
--                      vulnerability_count, trigger_reason,
--                      error_message, metadata_json
--   notification_policies: periodic_*, smart_*, immediate_enabled,
--                          immediate_min_*, digest_enabled, digest_min_*,
--                          digest_last_watermark_at, intelligent_*
-- Tablas EXCLUIDAS: local_signup_requests, notification_job_runs,
--   intelligent_notification_findings,
--   intelligent_notification_subscriber_matches,
--   intelligent_notification_test_runs, api_keys
-- ============================================================

-- ────────────────────────────────────────────────────────────
-- USUARIOS
-- ────────────────────────────────────────────────────────────

CREATE TABLE `users` (
  `id`                 INT            NOT NULL AUTO_INCREMENT,
  `email`              VARCHAR(191)   NOT NULL,
  `password_hash`      VARCHAR(191)   NULL,
  `name`               VARCHAR(191)   NOT NULL,
  `role`               VARCHAR(191)   NOT NULL DEFAULT 'USER',
  `can_login`          BOOLEAN        NOT NULL DEFAULT true,
  `is_subscriber`      BOOLEAN        NOT NULL DEFAULT false,
  `notification_email` VARCHAR(191)   NULL,
  `contact_person`     VARCHAR(191)   NULL,
  `department`         VARCHAR(191)   NULL,
  `phone`              VARCHAR(191)   NULL,
  `notes`              TEXT           NULL,
  `is_active`          BOOLEAN        NOT NULL DEFAULT true,
  `created_at`         DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`         DATETIME(3)    NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `users_email_key` (`email`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `user_sessions` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `user_id`    INT          NOT NULL,
  `token_hash` VARCHAR(191) NOT NULL,
  `ip_address` VARCHAR(191) NULL,
  `user_agent` VARCHAR(191) NULL,
  `expires_at` DATETIME(3)  NOT NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (`id`),
  INDEX `user_sessions_token_hash_idx` (`token_hash`),
  INDEX `user_sessions_user_id_idx`    (`user_id`),
  INDEX `user_sessions_expires_at_idx` (`expires_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `login_attempts` (
  `id`           INT          NOT NULL AUTO_INCREMENT,
  `email`        VARCHAR(191) NOT NULL,
  `ip_address`   VARCHAR(191) NOT NULL,
  `attempted_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `success`      BOOLEAN      NOT NULL DEFAULT false,

  PRIMARY KEY (`id`),
  INDEX `login_attempts_email_attempted_at_idx`      (`email`, `attempted_at`),
  INDEX `login_attempts_ip_address_attempted_at_idx` (`ip_address`, `attempted_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `password_resets` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(191) NOT NULL,
  `token_hash` VARCHAR(191) NOT NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `expires_at` DATETIME(3)  NOT NULL,
  `used_at`    DATETIME(3)  NULL,

  PRIMARY KEY (`id`),
  INDEX `password_resets_token_hash_idx` (`token_hash`),
  INDEX `password_resets_email_idx`      (`email`),
  INDEX `password_resets_expires_at_idx` (`expires_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- VULNERABILIDADES
-- ────────────────────────────────────────────────────────────

CREATE TABLE `vulnerabilities` (
  `id`                       INT          NOT NULL AUTO_INCREMENT,
  `cve_id`                   VARCHAR(191) NOT NULL,
  `description`              MEDIUMTEXT   NULL,
  `published_at`             DATETIME(3)  NOT NULL,
  `last_modified_at`         DATETIME(3)  NULL,

  `cvss_v31_score`           DOUBLE       NULL,
  `cvss_v31_vector`          VARCHAR(191) NULL,
  `cvss_v31_severity`        VARCHAR(191) NULL,
  `epss_score`               DOUBLE       NULL,
  `epss_percentile`          DOUBLE       NULL,

  `is_known_exploited`       BOOLEAN      NOT NULL DEFAULT false,
  `kev_date_added`           DATETIME(3)  NULL,
  `kev_due_date`             DATETIME(3)  NULL,
  `has_public_exploit`       BOOLEAN      NOT NULL DEFAULT false,
  `exploit_references`       LONGTEXT     NULL,
  `references`               LONGTEXT     NULL,

  `affected_products`        LONGTEXT     NULL,
  `remediation_info`         LONGTEXT     NULL,
  `operational_risk_score`   DOUBLE       NULL,
  `operational_risk_tier`    VARCHAR(191) NULL,
  `risk_signals`             LONGTEXT     NULL,
  `data_confidence`          DOUBLE       NULL,

  `exploit_status`           VARCHAR(191) NULL,
  `exploit_confidence`       DOUBLE       NULL,
  `exploit_first_seen_at`    DATETIME(3)  NULL,
  `exploit_last_checked_at`  DATETIME(3)  NULL,

  `primary_vendor`            VARCHAR(191) NULL,
  `primary_product`           VARCHAR(191) NULL,
  `affected_products_detailed` LONGTEXT    NULL,
  `affected_cpes`             LONGTEXT     NULL,

  `patch_available`          BOOLEAN      NULL,
  `patch_priority`           VARCHAR(191) NULL,
  `fixed_versions`           LONGTEXT     NULL,
  `workarounds`              LONGTEXT     NULL,
  `detection_opportunities`  LONGTEXT     NULL,

  `source_count`             INT          NOT NULL DEFAULT 1,
  `sources_present`          LONGTEXT     NULL,
  `canonical_source`         VARCHAR(191) NULL,
  `record_status`            VARCHAR(191) NULL,
  `last_change_detected_at`  DATETIME(3)  NULL,

  `source`                   VARCHAR(191) NOT NULL DEFAULT 'nvd',
  `raw_data`                 LONGTEXT     NULL,
  `processing_status`        VARCHAR(191) NOT NULL DEFAULT 'new',
  `first_seen_at`            DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `enriched_at`              DATETIME(3)  NULL,

  `created_at`               DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`               DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `vulnerabilities_cve_id_key`              (`cve_id`),
  INDEX `vulnerabilities_cve_id_idx`                    (`cve_id`),
  INDEX `vulnerabilities_cvss_v31_severity_idx`         (`cvss_v31_severity`),
  INDEX `vulnerabilities_published_at_idx`              (`published_at` DESC),
  INDEX `vulnerabilities_is_known_exploited_idx`        (`is_known_exploited`),
  INDEX `vulnerabilities_processing_status_idx`         (`processing_status`),
  INDEX `vulnerabilities_epss_score_idx`                (`epss_score` DESC),
  INDEX `vulnerabilities_first_seen_at_idx`             (`first_seen_at` DESC),
  INDEX `vulnerabilities_operational_risk_score_idx`    (`operational_risk_score`),
  INDEX `vulnerabilities_operational_risk_tier_idx`     (`operational_risk_tier`),
  INDEX `vulnerabilities_primary_vendor_idx`            (`primary_vendor`),
  INDEX `vulnerabilities_primary_product_idx`           (`primary_product`),
  INDEX `vulnerabilities_exploit_status_idx`            (`exploit_status`),
  INDEX `vulnerabilities_record_status_idx`             (`record_status`),
  INDEX `vulnerabilities_last_change_detected_at_idx`  (`last_change_detected_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `vulnerability_change_events` (
  `id`               INT          NOT NULL AUTO_INCREMENT,
  `vulnerability_id` INT          NOT NULL,
  `cve_id`           VARCHAR(191) NOT NULL,
  `source`           VARCHAR(191) NOT NULL,
  `change_type`      VARCHAR(191) NOT NULL,
  `field_name`       VARCHAR(191) NOT NULL,
  `old_value`        LONGTEXT     NULL,
  `new_value`        LONGTEXT     NULL,
  `is_significant`   BOOLEAN      NOT NULL DEFAULT false,
  `summary`          TEXT         NULL,
  `detected_at`      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (`id`),
  INDEX `vulnerability_change_events_vulnerability_id_detected_at_idx` (`vulnerability_id`, `detected_at` DESC),
  INDEX `vulnerability_change_events_cve_id_detected_at_idx`           (`cve_id`, `detected_at` DESC),
  INDEX `vulnerability_change_events_change_type_idx`                  (`change_type`),
  INDEX `vulnerability_change_events_is_significant_detected_at_idx`   (`is_significant`, `detected_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `vulnerability_source_records` (
  `id`                 INT          NOT NULL AUTO_INCREMENT,
  `vulnerability_id`   INT          NOT NULL,
  `cve_id`             VARCHAR(191) NOT NULL,
  `source_name`        VARCHAR(191) NOT NULL,
  `source_record_id`   VARCHAR(191) NULL,
  `source_url`         VARCHAR(191) NULL,
  `source_published_at` DATETIME(3) NULL,
  `source_modified_at` DATETIME(3)  NULL,
  `confidence`         DOUBLE       NULL,
  `raw_payload`        LONGTEXT     NULL,
  `normalized_data`    LONGTEXT     NULL,
  `first_seen_at`      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_seen_at`       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `is_canonical`       BOOLEAN      NOT NULL DEFAULT false,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `vulnerability_source_records_cve_id_source_name_key` (`cve_id`, `source_name`),
  INDEX `vulnerability_source_records_vulnerability_id_idx`          (`vulnerability_id`),
  INDEX `vulnerability_source_records_source_name_last_seen_at_idx`  (`source_name`, `last_seen_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- COLLECTOR
-- ────────────────────────────────────────────────────────────

CREATE TABLE `collector_source_health` (
  `id`              INT          NOT NULL AUTO_INCREMENT,
  `source`          VARCHAR(191) NOT NULL,
  `run_date`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `fetch_status`    VARCHAR(191) NOT NULL,
  `items_fetched`   INT          NOT NULL DEFAULT 0,
  `items_processed` INT          NOT NULL DEFAULT 0,
  `items_errored`   INT          NOT NULL DEFAULT 0,
  `duration_ms`     INT          NULL,
  `anomaly_flags`   LONGTEXT     NULL,
  `error_message`   TEXT         NULL,

  PRIMARY KEY (`id`),
  INDEX `collector_source_health_source_run_date_idx` (`source`, `run_date` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `collector_runs` (
  `id`               INT          NOT NULL AUTO_INCREMENT,
  `started_at`       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at`      DATETIME(3)  NULL,
  `source`           VARCHAR(191) NOT NULL,
  `cves_fetched`     INT          NOT NULL DEFAULT 0,
  `cves_new`         INT          NOT NULL DEFAULT 0,
  `cves_updated`     INT          NOT NULL DEFAULT 0,
  `manufacturers_new` INT         NOT NULL DEFAULT 0,
  `products_new`     INT          NOT NULL DEFAULT 0,
  `status`           VARCHAR(191) NOT NULL,
  `error_message`    VARCHAR(191) NULL,
  `duration_ms`      INT          NULL,
  `triggered_by`     INT          NULL,

  PRIMARY KEY (`id`),
  INDEX `collector_runs_started_at_idx` (`started_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- ACTIVOS Y DEPENDENCIAS
-- ────────────────────────────────────────────────────────────

CREATE TABLE `product_assets` (
  `id`             INT          NOT NULL AUTO_INCREMENT,
  `name`           VARCHAR(191) NOT NULL,
  `slug`           VARCHAR(191) NOT NULL,
  `owner`          VARCHAR(191) NULL,
  `environment`    VARCHAR(191) NULL,
  `criticality`    VARCHAR(191) NULL,
  `product_type`   VARCHAR(191) NOT NULL DEFAULT 'unknown',
  `source`         VARCHAR(191) NOT NULL DEFAULT 'manual',
  `version`        VARCHAR(191) NULL,
  `repository_url` VARCHAR(191) NULL,
  `is_active`      BOOLEAN      NOT NULL DEFAULT true,
  `last_seen_at`   DATETIME(3)  NULL,
  `metadata`       LONGTEXT     NULL,
  `created_at`     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `product_assets_slug_key` (`slug`),
  INDEX `product_assets_name_idx`        (`name`),
  INDEX `product_assets_slug_idx`        (`slug`),
  INDEX `product_assets_environment_idx` (`environment`),
  INDEX `product_assets_criticality_idx` (`criticality`),
  INDEX `product_assets_product_type_idx` (`product_type`),
  INDEX `product_assets_is_active_idx`   (`is_active`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `dependency_evidence_imports` (
  `id`                 INT          NOT NULL AUTO_INCREMENT,
  `product_asset_id`   INT          NOT NULL,
  `import_type`        VARCHAR(191) NOT NULL,
  `import_status`      VARCHAR(191) NOT NULL DEFAULT 'pending',
  `imported_at`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `checksum`           VARCHAR(191) NULL,
  `source_name`        VARCHAR(191) NULL,
  `source_path`        VARCHAR(191) NULL,
  `raw_payload`        LONGTEXT     NULL,
  `normalized_summary` LONGTEXT     NULL,
  `error_message`      TEXT         NULL,
  `created_at`         DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`         DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  INDEX `dependency_evidence_imports_product_asset_id_idx` (`product_asset_id`),
  INDEX `dependency_evidence_imports_import_type_idx`      (`import_type`),
  INDEX `dependency_evidence_imports_import_status_idx`    (`import_status`),
  INDEX `dependency_evidence_imports_imported_at_idx`      (`imported_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `product_dependency_inventory` (
  `id`                           INT          NOT NULL AUTO_INCREMENT,
  `product_asset_id`             INT          NOT NULL,
  `dependency_evidence_import_id` INT         NULL,
  `component_name`               VARCHAR(191) NOT NULL,
  `component_vendor`             VARCHAR(191) NULL,
  `component_version`            VARCHAR(191) NULL,
  `component_type`               VARCHAR(191) NOT NULL DEFAULT 'unknown',
  `ecosystem`                    VARCHAR(191) NOT NULL DEFAULT 'unknown',
  `purl`                         VARCHAR(191) NULL,
  `cpe`                          VARCHAR(191) NULL,
  `evidence_source`              VARCHAR(191) NOT NULL,
  `evidence_path`                VARCHAR(191) NULL,
  `direct_dependency`            BOOLEAN      NULL,
  `dev_dependency`               BOOLEAN      NULL,
  `reachable`                    BOOLEAN      NULL,
  `confidence`                   DOUBLE       NULL,
  `first_seen_at`                DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_seen_at`                 DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `raw_evidence`                 LONGTEXT     NULL,
  `created_at`                   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`                   DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  INDEX `product_dependency_inventory_product_asset_id_idx`              (`product_asset_id`),
  INDEX `product_dependency_inventory_dependency_evidence_import_id_idx` (`dependency_evidence_import_id`),
  INDEX `product_dependency_inventory_component_name_idx`                (`component_name`),
  INDEX `product_dependency_inventory_component_vendor_idx`              (`component_vendor`),
  INDEX `product_dependency_inventory_component_version_idx`             (`component_version`),
  INDEX `product_dependency_inventory_component_type_idx`                (`component_type`),
  INDEX `product_dependency_inventory_ecosystem_idx`                     (`ecosystem`),
  INDEX `product_dependency_inventory_purl_idx`                          (`purl`),
  INDEX `product_dependency_inventory_cpe_idx`                           (`cpe`),
  INDEX `product_dependency_inventory_evidence_source_idx`               (`evidence_source`),
  INDEX `product_dependency_inventory_last_seen_at_idx`                  (`last_seen_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `vulnerability_product_impacts` (
  `id`                       INT          NOT NULL AUTO_INCREMENT,
  `vulnerability_id`         INT          NOT NULL,
  `cve_id`                   VARCHAR(191) NOT NULL,
  `product_asset_id`         INT          NOT NULL,
  `dependency_inventory_id`  INT          NULL,
  `impact_type`              VARCHAR(191) NOT NULL,
  `impact_status`            VARCHAR(191) NOT NULL DEFAULT 'open',
  `confidence`               DOUBLE       NULL,
  `evidence_source`          VARCHAR(191) NOT NULL,
  `evidence_summary`         TEXT         NULL,
  `matched_component_name`   VARCHAR(191) NULL,
  `matched_component_vendor` VARCHAR(191) NULL,
  `matched_component_version` VARCHAR(191) NULL,
  `fixed_version`            VARCHAR(191) NULL,
  `is_direct_dependency`     BOOLEAN      NULL,
  `is_runtime_relevant`      BOOLEAN      NULL,
  `reachable`                BOOLEAN      NULL,
  `notes`                    TEXT         NULL,
  `first_detected_at`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_validated_at`        DATETIME(3)  NULL,
  `resolved_at`              DATETIME(3)  NULL,
  `created_at`               DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`               DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `vpi_vuln_product_dep_unique`
    (`vulnerability_id`, `product_asset_id`, `dependency_inventory_id`),
  INDEX `vulnerability_product_impacts_vulnerability_id_idx`       (`vulnerability_id`),
  INDEX `vulnerability_product_impacts_cve_id_idx`                 (`cve_id`),
  INDEX `vulnerability_product_impacts_product_asset_id_idx`       (`product_asset_id`),
  INDEX `vulnerability_product_impacts_dependency_inventory_id_idx` (`dependency_inventory_id`),
  INDEX `vulnerability_product_impacts_impact_type_idx`            (`impact_type`),
  INDEX `vulnerability_product_impacts_impact_status_idx`          (`impact_status`),
  INDEX `vulnerability_product_impacts_confidence_idx`             (`confidence`),
  INDEX `vulnerability_product_impacts_evidence_source_idx`        (`evidence_source`),
  INDEX `vulnerability_product_impacts_first_detected_at_idx`      (`first_detected_at` DESC),
  INDEX `vulnerability_product_impacts_last_validated_at_idx`      (`last_validated_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- INFORMES Y CONFIGURACIÓN
-- ────────────────────────────────────────────────────────────

CREATE TABLE `vulnerability_reports` (
  `id`             INT          NOT NULL AUTO_INCREMENT,
  `report_date`    DATETIME(3)  NOT NULL,
  `period_start`   DATETIME(3)  NOT NULL,
  `period_end`     DATETIME(3)  NOT NULL,
  `total_cves`     INT          NOT NULL,
  `critical_count` INT          NOT NULL DEFAULT 0,
  `high_count`     INT          NOT NULL DEFAULT 0,
  `exploited_count` INT         NOT NULL DEFAULT 0,
  `file_path`      VARCHAR(191) NULL,
  `generated_by`   INT          NULL,
  `created_at`     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `api_configurations` (
  `id`                INT          NOT NULL AUTO_INCREMENT,
  `name`              VARCHAR(191) NOT NULL,
  `slug`              VARCHAR(191) NOT NULL,
  `provider`          VARCHAR(191) NOT NULL,
  `api_key_encrypted` VARCHAR(191) NULL,
  `endpoint_url`      VARCHAR(191) NULL,
  `settings`          LONGTEXT     NULL,
  `is_active`         BOOLEAN      NOT NULL DEFAULT true,
  `last_used_at`      DATETIME(3)  NULL,
  `created_by`        INT          NULL,
  `created_at`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`        DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `api_configurations_slug_key` (`slug`),
  INDEX `api_configurations_provider_idx`    (`provider`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- NOTIFICACIONES
-- ────────────────────────────────────────────────────────────

CREATE TABLE `notification_logs` (
  `id`             INT          NOT NULL AUTO_INCREMENT,
  `recipient_email` VARCHAR(191) NOT NULL,
  `recipient_name`  VARCHAR(191) NULL,
  `subject`        VARCHAR(191) NOT NULL,
  `html_content`   TEXT         NOT NULL,
  `cve_ids`        VARCHAR(191) NOT NULL DEFAULT '[]',
  `status`         VARCHAR(191) NOT NULL DEFAULT 'sent',
  `sent_at`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (`id`),
  INDEX `notification_logs_sent_at_idx` (`sent_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- TAGS Y RELACIONES M2M
-- ────────────────────────────────────────────────────────────

CREATE TABLE `vulnerability_tags` (
  `id`               INT          NOT NULL AUTO_INCREMENT,
  `name`             VARCHAR(191) NOT NULL,
  `color`            VARCHAR(191) NOT NULL DEFAULT '#3B6CB5',
  `is_auto_generated` BOOLEAN     NOT NULL DEFAULT false,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `vulnerability_tags_name_key` (`name`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Tabla implícita M2M generada por Prisma (Vulnerability <-> VulnerabilityTag)
CREATE TABLE `_VulnerabilityToVulnerabilityTag` (
  `A` INT NOT NULL,
  `B` INT NOT NULL,

  UNIQUE INDEX `_VulnerabilityToVulnerabilityTag_AB_unique` (`A`, `B`),
  INDEX `_VulnerabilityToVulnerabilityTag_B_index` (`B`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `vulnerability_notifications` (
  `id`                  INT          NOT NULL AUTO_INCREMENT,
  `vulnerability_id`    INT          NOT NULL,
  `contact_id`          INT          NULL,
  `subscriber_user_id`  INT          NULL,
  `recipient_email`     VARCHAR(191) NOT NULL,
  `recipient_name`      VARCHAR(191) NULL,
  `sent_at`             DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `status`              VARCHAR(191) NOT NULL DEFAULT 'sent',
  `notification_log_id` INT          NULL,

  PRIMARY KEY (`id`),
  INDEX `vulnerability_notifications_vulnerability_id_idx`   (`vulnerability_id`),
  INDEX `vulnerability_notifications_contact_id_idx`         (`contact_id`),
  INDEX `vulnerability_notifications_subscriber_user_id_idx` (`subscriber_user_id`),
  INDEX `vulnerability_notifications_sent_at_idx`            (`sent_at` DESC)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- CATÁLOGO SOFTWARE
-- ────────────────────────────────────────────────────────────

CREATE TABLE `software_catalog` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `vendor`     VARCHAR(191) NOT NULL,
  `product`    VARCHAR(191) NOT NULL,
  `versions`   TEXT         NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `software_catalog_vendor_product_key` (`vendor`, `product`),
  INDEX `software_catalog_vendor_idx`  (`vendor`),
  INDEX `software_catalog_product_idx` (`product`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `manufacturers` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `name`       VARCHAR(191) NOT NULL,
  `is_active`  BOOLEAN      NOT NULL DEFAULT true,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `manufacturers_name_key` (`name`),
  INDEX `manufacturers_name_idx`        (`name`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- SUSCRIPTORES Y SISTEMAS
-- ────────────────────────────────────────────────────────────

CREATE TABLE `user_subscriptions` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `user_id`    INT          NOT NULL,
  `vendor`     VARCHAR(191) NOT NULL,
  `product`    VARCHAR(191) NOT NULL,
  `versions`   TEXT         NULL,
  `is_active`  BOOLEAN      NOT NULL DEFAULT true,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `user_subscriptions_user_id_vendor_product_key` (`user_id`, `vendor`, `product`),
  INDEX `user_subscriptions_user_id_idx`      (`user_id`),
  INDEX `user_subscriptions_vendor_product_idx` (`vendor`, `product`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `subscriber_owned_systems` (
  `id`                INT          NOT NULL AUTO_INCREMENT,
  `subscriber_user_id` INT         NOT NULL,
  `external_id`       VARCHAR(191) NOT NULL,
  `source`            VARCHAR(191) NOT NULL DEFAULT 'manual',
  `hostname`          VARCHAR(191) NOT NULL,
  `fqdn`              VARCHAR(191) NULL,
  `platform`          VARCHAR(191) NULL,
  `os_version`        VARCHAR(191) NULL,
  `risk_level`        VARCHAR(191) NULL,
  `health_status`     VARCHAR(191) NULL,
  `onboarding_status` VARCHAR(191) NULL,
  `last_seen_at`      DATETIME(3)  NULL,
  `is_selected`       BOOLEAN      NOT NULL DEFAULT true,
  `is_active`         BOOLEAN      NOT NULL DEFAULT true,
  `tags`              TEXT         NULL,
  `raw_data`          LONGTEXT     NULL,
  `created_at`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`        DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `subscriber_owned_systems_subscriber_user_id_external_id_key` (`subscriber_user_id`, `external_id`),
  INDEX `subscriber_owned_systems_subscriber_user_id_idx` (`subscriber_user_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `defender_action_requests` (
  `id`                  INT          NOT NULL AUTO_INCREMENT,
  `subscriber_user_id`  INT          NOT NULL,
  `action_id`           VARCHAR(191) NOT NULL,
  `action_name`         VARCHAR(191) NOT NULL,
  `system_external_ids` TEXT         NOT NULL,
  `status`              VARCHAR(191) NOT NULL DEFAULT 'planned',
  `notes`               TEXT         NULL,
  `requested_by`        VARCHAR(191) NULL,
  `created_at`          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`          DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  INDEX `defender_action_requests_subscriber_user_id_idx` (`subscriber_user_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `subscriber_patched_cves` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `user_id`    INT          NOT NULL,
  `cve_id`     VARCHAR(191) NOT NULL,
  `patched_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `notes`      TEXT         NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `subscriber_patched_cves_user_id_cve_id_key` (`user_id`, `cve_id`),
  INDEX `subscriber_patched_cves_user_id_idx` (`user_id`),
  INDEX `subscriber_patched_cves_cve_id_idx`  (`cve_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- NOTIFICACIONES INTELIGENTES (SMART) — tablas baseline
-- ────────────────────────────────────────────────────────────

CREATE TABLE `smart_notification_reports` (
  `id`                 INT          NOT NULL AUTO_INCREMENT,
  `subscriber_user_id` INT          NOT NULL,
  `period_start`       DATETIME(3)  NOT NULL,
  `period_end`         DATETIME(3)  NOT NULL,
  `recipient_email`    VARCHAR(191) NOT NULL,
  `subject`            VARCHAR(191) NULL,
  `status`             VARCHAR(191) NOT NULL DEFAULT 'generated',
  `ai_provider`        VARCHAR(191) NULL,
  `ai_model`           VARCHAR(191) NULL,
  `input_snapshot`     LONGTEXT     NULL,
  `analysis_json`      LONGTEXT     NULL,
  `sent_at`            DATETIME(3)  NULL,
  `error_message`      TEXT         NULL,
  `created_at`         DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`         DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  INDEX `smart_notification_reports_subscriber_user_id_idx` (`subscriber_user_id`),
  INDEX `smart_notification_reports_period_end_idx`         (`period_end` DESC),
  INDEX `smart_notification_reports_status_idx`             (`status`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- POLÍTICAS DE NOTIFICACIÓN
-- (sólo columnas previas a 20260323200000 y 20260324143000)
-- ────────────────────────────────────────────────────────────

CREATE TABLE `notification_policies` (
  `id`                    INT          NOT NULL AUTO_INCREMENT,
  `user_id`               INT          NOT NULL,
  `immediate_for_critical`    BOOLEAN  NOT NULL DEFAULT true,
  `immediate_for_exploitable` BOOLEAN  NOT NULL DEFAULT true,
  `min_cvss_for_immediate`    DOUBLE   NOT NULL DEFAULT 9.0,
  `digest_frequency`      VARCHAR(191) NOT NULL DEFAULT 'daily',
  `digest_hour`           INT          NOT NULL DEFAULT 8,
  `digest_day_of_week`    INT          NULL,
  `is_active`             BOOLEAN      NOT NULL DEFAULT true,
  `created_at`            DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`            DATETIME(3)  NOT NULL,

  PRIMARY KEY (`id`),
  UNIQUE INDEX `notification_policies_user_id_key` (`user_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `pending_digest_notifications` (
  `id`               INT          NOT NULL AUTO_INCREMENT,
  `user_id`          INT          NOT NULL,
  `vulnerability_id` INT          NOT NULL,
  `vendor`           VARCHAR(191) NOT NULL,
  `created_at`       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (`id`),
  UNIQUE INDEX `pending_digest_notifications_user_id_vulnerability_id_key` (`user_id`, `vulnerability_id`),
  INDEX `pending_digest_notifications_user_id_idx` (`user_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ────────────────────────────────────────────────────────────
-- FOREIGN KEYS
-- ────────────────────────────────────────────────────────────

ALTER TABLE `user_sessions`
  ADD CONSTRAINT `user_sessions_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `vulnerability_change_events`
  ADD CONSTRAINT `vulnerability_change_events_vulnerability_id_fkey`
    FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `vulnerability_source_records`
  ADD CONSTRAINT `vulnerability_source_records_vulnerability_id_fkey`
    FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `dependency_evidence_imports`
  ADD CONSTRAINT `dependency_evidence_imports_product_asset_id_fkey`
    FOREIGN KEY (`product_asset_id`) REFERENCES `product_assets`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `product_dependency_inventory`
  ADD CONSTRAINT `product_dependency_inventory_product_asset_id_fkey`
    FOREIGN KEY (`product_asset_id`) REFERENCES `product_assets`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `product_dependency_inventory_dependency_evidence_import_id_fkey`
    FOREIGN KEY (`dependency_evidence_import_id`) REFERENCES `dependency_evidence_imports`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `vulnerability_product_impacts`
  ADD CONSTRAINT `vulnerability_product_impacts_vulnerability_id_fkey`
    FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `vulnerability_product_impacts_product_asset_id_fkey`
    FOREIGN KEY (`product_asset_id`) REFERENCES `product_assets`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `vulnerability_product_impacts_dependency_inventory_id_fkey`
    FOREIGN KEY (`dependency_inventory_id`) REFERENCES `product_dependency_inventory`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `vulnerability_reports`
  ADD CONSTRAINT `vulnerability_reports_generated_by_fkey`
    FOREIGN KEY (`generated_by`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `collector_runs`
  ADD CONSTRAINT `collector_runs_triggered_by_fkey`
    FOREIGN KEY (`triggered_by`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `api_configurations`
  ADD CONSTRAINT `api_configurations_created_by_fkey`
    FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `vulnerability_notifications`
  ADD CONSTRAINT `vulnerability_notifications_vulnerability_id_fkey`
    FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `vulnerability_notifications_subscriber_user_id_fkey`
    FOREIGN KEY (`subscriber_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `user_subscriptions`
  ADD CONSTRAINT `user_subscriptions_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `subscriber_owned_systems`
  ADD CONSTRAINT `subscriber_owned_systems_subscriber_user_id_fkey`
    FOREIGN KEY (`subscriber_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `defender_action_requests`
  ADD CONSTRAINT `defender_action_requests_subscriber_user_id_fkey`
    FOREIGN KEY (`subscriber_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `subscriber_patched_cves`
  ADD CONSTRAINT `subscriber_patched_cves_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `smart_notification_reports`
  ADD CONSTRAINT `smart_notification_reports_subscriber_user_id_fkey`
    FOREIGN KEY (`subscriber_user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `notification_policies`
  ADD CONSTRAINT `notification_policies_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `pending_digest_notifications`
  ADD CONSTRAINT `pending_digest_notifications_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `pending_digest_notifications_vulnerability_id_fkey`
    FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `_VulnerabilityToVulnerabilityTag`
  ADD CONSTRAINT `_VulnerabilityToVulnerabilityTag_A_fkey`
    FOREIGN KEY (`A`) REFERENCES `vulnerabilities`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `_VulnerabilityToVulnerabilityTag_B_fkey`
    FOREIGN KEY (`B`) REFERENCES `vulnerability_tags`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
