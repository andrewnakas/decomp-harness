-- A store whose base is computed during the call is a suspicion, not a verdict:
-- the window builder can often still read the base before the call. Screening
-- records the count so ranking can use it without gating on it.
ALTER TABLE function ADD COLUMN gate2_suspects INTEGER DEFAULT 0;
