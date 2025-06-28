CREATE TABLE IF NOT EXISTS confessions (
  id BIGINT PRIMARY KEY,
  message TEXT NOT NULL,
  time TEXT,
  photo TEXT,
  likes INTEGER DEFAULT 0
);
