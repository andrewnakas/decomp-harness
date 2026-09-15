-- Whether the decompiler produced usable C for a function. Only halt_baddata
-- counts as failure: an unnamed branch target is still real code, and treating
-- it as a failure would push 186 of the audio corpus's 1,694 functions onto the
-- more expensive assembly path for no reason.
ALTER TABLE function ADD COLUMN decompile_ok INTEGER;
ALTER TABLE function ADD COLUMN decompile_warnings TEXT;
