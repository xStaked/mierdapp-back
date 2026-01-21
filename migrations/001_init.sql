-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  avatar TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;

-- Poop logs table
CREATE TABLE IF NOT EXISTS poop_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  notes TEXT
);

ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS id UUID;
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS user_id UUID;
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ;
ALTER TABLE poop_logs ADD COLUMN IF NOT EXISTS notes TEXT;

-- Friendships table
CREATE TABLE IF NOT EXISTS friendships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, friend_id)
);

ALTER TABLE friendships ADD COLUMN IF NOT EXISTS id UUID;
ALTER TABLE friendships ADD COLUMN IF NOT EXISTS user_id UUID;
ALTER TABLE friendships ADD COLUMN IF NOT EXISTS friend_id UUID;
ALTER TABLE friendships ADD COLUMN IF NOT EXISTS status TEXT;
ALTER TABLE friendships ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_poop_logs_user_id ON poop_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_poop_logs_timestamp ON poop_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships(user_id);
CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_id);
