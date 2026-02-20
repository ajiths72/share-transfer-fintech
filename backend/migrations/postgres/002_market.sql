CREATE TABLE IF NOT EXISTS market_symbols (
  symbol TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  last_price DOUBLE PRECISION NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS market_orders (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  symbol TEXT NOT NULL REFERENCES market_symbols(symbol),
  quantity BIGINT NOT NULL,
  price_per_share DOUBLE PRECISION NOT NULL,
  total_amount DOUBLE PRECISION NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('EXECUTED')),
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_market_orders_user_id ON market_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_market_orders_symbol ON market_orders(symbol);
