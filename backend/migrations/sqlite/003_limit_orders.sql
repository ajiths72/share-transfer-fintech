CREATE TABLE IF NOT EXISTS limit_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  symbol TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  limit_price REAL NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING','EXECUTED','CANCELED')),
  created_at TEXT NOT NULL,
  canceled_at TEXT,
  executed_at TEXT,
  executed_price REAL,
  total_amount REAL,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(symbol) REFERENCES market_symbols(symbol)
);

CREATE INDEX IF NOT EXISTS idx_limit_orders_user_id ON limit_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_limit_orders_status ON limit_orders(status);
