-- M1.5: keep a bounded presentation-safe explanation of terminal chain failure.
-- Raw provider stderr remains Evidence; this column is only for user-facing CoreError text.
ALTER TABLE chain_runs
    ADD COLUMN error_message TEXT
    CHECK(error_message IS NULL OR length(error_message) <= 512);
