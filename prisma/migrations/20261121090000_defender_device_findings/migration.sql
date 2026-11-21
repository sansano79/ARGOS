-- Fase 1 Defender: hallazgos de vulnerabilidades por equipo y ejecuciones de sync.
-- Aditiva: no modifica tablas existentes.

-- CreateTable
CREATE TABLE `device_vulnerability_findings` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `team_system_id` INTEGER NOT NULL,
    `device_external_id` VARCHAR(64) NOT NULL,
    `cve_id` VARCHAR(32) NOT NULL,
    `vulnerability_id` INTEGER NULL,
    `product_vendor` VARCHAR(191) NOT NULL DEFAULT '',
    `product_name` VARCHAR(191) NOT NULL,
    `product_version` VARCHAR(191) NOT NULL DEFAULT '',
    `defender_severity` VARCHAR(20) NULL,
    `defender_cvss` DOUBLE NULL,
    `exploitability_level` VARCHAR(40) NULL,
    `fixing_kb_id` VARCHAR(64) NULL,
    `recommended_update` TEXT NULL,
    `disk_paths` LONGTEXT NULL,
    `registry_paths` LONGTEXT NULL,
    `status` VARCHAR(16) NOT NULL DEFAULT 'open',
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `fixed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `device_vulnerability_findings_team_system_id_status_idx`(`team_system_id`, `status`),
    INDEX `device_vulnerability_findings_cve_id_idx`(`cve_id`),
    INDEX `device_vulnerability_findings_vulnerability_id_idx`(`vulnerability_id`),
    INDEX `device_vulnerability_findings_fixing_kb_id_idx`(`fixing_kb_id`),
    UNIQUE INDEX `dvf_device_cve_product_key`(`team_system_id`, `cve_id`, `product_vendor`, `product_name`, `product_version`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `defender_sync_runs` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `mode` VARCHAR(16) NOT NULL,
    `status` VARCHAR(16) NOT NULL DEFAULT 'queued',
    `triggered_by` INTEGER NULL,
    `since_time` DATETIME(3) NULL,
    `started_at` DATETIME(3) NULL,
    `finished_at` DATETIME(3) NULL,
    `duration_ms` INTEGER NULL,
    `devices_seen` INTEGER NOT NULL DEFAULT 0,
    `devices_upserted` INTEGER NOT NULL DEFAULT 0,
    `devices_deactivated` INTEGER NOT NULL DEFAULT 0,
    `devices_failed` INTEGER NOT NULL DEFAULT 0,
    `findings_upserted` INTEGER NOT NULL DEFAULT 0,
    `findings_fixed` INTEGER NOT NULL DEFAULT 0,
    `unknown_cves` INTEGER NOT NULL DEFAULT 0,
    `failures` LONGTEXT NULL,
    `error_message` TEXT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `defender_sync_runs_status_idx`(`status`),
    INDEX `defender_sync_runs_created_at_idx`(`created_at` DESC),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `device_vulnerability_findings` ADD CONSTRAINT `device_vulnerability_findings_team_system_id_fkey` FOREIGN KEY (`team_system_id`) REFERENCES `team_systems`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `device_vulnerability_findings` ADD CONSTRAINT `device_vulnerability_findings_vulnerability_id_fkey` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

