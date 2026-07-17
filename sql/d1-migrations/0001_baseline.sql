-- Native D1 migration baseline.
--
-- Databases created before this migration system are brought to the baseline by
-- the legacy compatibility step in push-cloudflare.yaml. New databases import
-- sql/schema.sql first. This no-op migration lets Wrangler start tracking both
-- cases from the same point without replaying historical migrations.
SELECT 1;
