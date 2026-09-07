-- Design Club application intake.
-- Apply with:
--   npx wrangler d1 execute designclub-applications --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS applications (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  email       TEXT NOT NULL,
  grade       TEXT NOT NULL,
  role        TEXT NOT NULL,
  experience  TEXT,
  why         TEXT NOT NULL,
  ip          TEXT,
  user_agent  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  -- Cached AI role suggestions (JSON), filled in on demand from the admin page.
  ai_review      TEXT,
  ai_reviewed_at TEXT
);

-- Supports the newest-first review query and the per-IP rate limit check.
CREATE INDEX IF NOT EXISTS idx_applications_created_at ON applications (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_applications_ip_created ON applications (ip, created_at);

-- Failed admin password attempts, used to throttle guessing.
CREATE TABLE IF NOT EXISTS login_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ip         TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip, created_at);
