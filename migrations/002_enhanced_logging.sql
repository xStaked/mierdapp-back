-- Add new columns to poop_logs for enhanced tracking
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS latitude DECIMAL(10, 8);
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS longitude DECIMAL(11, 8);
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS location_name TEXT;
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS photo_url TEXT;
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS rating INTEGER CHECK (rating >= 1 AND rating <= 5);
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS duration_minutes INTEGER;

-- Index for location-based queries
CREATE INDEX IF NOT EXISTS idx_poop_logs_location ON poop_logs(latitude, longitude);