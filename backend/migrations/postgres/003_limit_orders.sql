CREATE TABLE IF NOT EXISTS limit_orders (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  symbol TEXT NOT NULL REFERENCES market_symbols(symbol),
  quantity BIGINT NOT NULL,
  limit_price DOUBLE PRECISION NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING','EXECUTED','CANCELED')),
  created_at TIMESTAMPTZ NOT NULL,
  canceled_at TIMESTAMPTZ,
  executed_at TIMESTAMPTZ,
  executed_price DOUBLE PRECISION,
  total_amount DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_limit_orders_user_id ON limit_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_limit_orders_status ON limit_orders(status);
