CREATE TABLE IF NOT EXISTS market_symbols (
  symbol TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  last_price REAL NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS market_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  symbol TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  price_per_share REAL NOT NULL,
  total_amount REAL NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('EXECUTED')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(symbol) REFERENCES market_symbols(symbol)
);

CREATE INDEX IF NOT EXISTS idx_market_orders_user_id ON market_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_market_orders_symbol ON market_orders(symbol);
