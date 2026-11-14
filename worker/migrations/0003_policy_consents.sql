CREATE TABLE IF NOT EXISTS policy_consents (
  user_id TEXT PRIMARY KEY,
  guidelines_version TEXT NOT NULL,
  accepted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
