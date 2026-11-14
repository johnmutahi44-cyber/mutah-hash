-- Add the payout network selected by the member to withdrawal records.
-- This does not initiate or automate any cryptocurrency transfer.
ALTER TABLE withdrawals ADD COLUMN network TEXT;
