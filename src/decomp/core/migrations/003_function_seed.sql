-- Mark which corpus members are seeds, so closure results can be re-explained
-- without re-running the walk.
ALTER TABLE function ADD COLUMN seed INTEGER DEFAULT 0;
CREATE INDEX IF NOT EXISTS ix_function_seed ON function(seed);
