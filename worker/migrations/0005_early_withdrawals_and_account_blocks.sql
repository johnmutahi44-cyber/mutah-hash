-- Early withdrawal exception requests with private supporting documents and account block audit fields.
ALTER TABLE users ADD COLUMN block_reason TEXT;
ALTER TABLE users ADD COLUMN blocked_at TEXT;
CREATE TABLE IF NOT EXISTS early_withdrawal_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  payment_method TEXT NOT NULL,
  destination TEXT NOT NULL,
  document_name TEXT NOT NULL,
  document_mime TEXT NOT NULL,
  document_size INTEGER NOT NULL,
  document_blob BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),
  admin_reason TEXT,
  withdrawal_id TEXT,
  requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_early_withdrawal_user ON early_withdrawal_requests(user_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_early_withdrawal_status ON early_withdrawal_requests(status, requested_at DESC);
