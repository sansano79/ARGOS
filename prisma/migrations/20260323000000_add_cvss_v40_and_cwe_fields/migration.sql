-- AlterTable
ALTER TABLE `vulnerabilities`
  ADD COLUMN `cvss_v40_score` DOUBLE NULL,
  ADD COLUMN `cvss_v40_vector` VARCHAR(255) NULL,
  ADD COLUMN `cvss_v40_severity` VARCHAR(20) NULL,
  ADD COLUMN `cvss_version` VARCHAR(10) NULL,
  ADD COLUMN `cwe_ids` TEXT NULL,
  ADD COLUMN `cwe_names` TEXT NULL,
  ADD COLUMN `weakness_category` VARCHAR(50) NULL;

-- CreateIndex
CREATE INDEX `vulnerabilities_weakness_category_idx` ON `vulnerabilities`(`weakness_category`);
CREATE INDEX `vulnerabilities_cvss_version_idx` ON `vulnerabilities`(`cvss_version`);
