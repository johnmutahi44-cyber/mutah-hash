-- Persist the start time and progressive reward total for each 24-hour AIRDROP session.
ALTER TABLE users ADD COLUMN session_started_at TEXT;
ALTER TABLE users ADD COLUMN session_credited_sats INTEGER NOT NULL DEFAULT 0;

-- Give any already-running legacy session a fresh 24-hour window under the new reward rules.
UPDATE users
SET session_started_at=CURRENT_TIMESTAMP,
    session_ends_at=datetime('now','+24 hours'),
    session_credited_sats=0
WHERE session_active=1 AND session_started_at IS NULL;
