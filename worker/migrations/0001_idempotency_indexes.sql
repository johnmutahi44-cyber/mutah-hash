-- Prevent duplicate reward credits if payment/webhook events are retried.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_referral_reward_once
ON ledger(reference, entry_type)
WHERE reference IS NOT NULL AND entry_type='referral_reward';

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_hash_reward_once
ON ledger(reference, entry_type)
WHERE reference IS NOT NULL AND entry_type='hash_reward';

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_inactivity_reset_once
ON ledger(reference, entry_type)
WHERE reference IS NOT NULL AND entry_type='inactivity_reset';

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_withdrawal_paid_once
ON ledger(reference, entry_type)
WHERE reference IS NOT NULL AND entry_type='withdrawal_paid';
