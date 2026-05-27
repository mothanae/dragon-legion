-- Dragon Legion — Database Initialization
-- Creates TimescaleDB hypertable for operation logs (Module 11)

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dragon_legion;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dragon_legion;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO dragon_legion;
