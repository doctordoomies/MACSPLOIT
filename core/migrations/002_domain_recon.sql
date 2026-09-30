-- Phase 1A: allow a chain stage to pin the exact provider that runs it, so a
-- capability shared by more than one provider (e.g. subdomain discovery, now
-- offered by both the synthetic and Subfinder providers) is never ambiguous.
ALTER TABLE chain_stages ADD COLUMN provider_id TEXT;
