# Solana JSON-RPC Proxy

## Run

```bash
docker-compose up --build

curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}'
```

## Configuration

### Redis

- REDIS_ADDR: Redis address, e.g. redis:6379
- REDIS_PASSWORD: Redis password (empty if none)

### Solana RPC Nodes

- PROXY_NODES: Comma-separated list of Solana RPC nodes, e.g. https://api.devnet.solana.com,https://another-node.com
- PROXY_NODES_TIMEOUT: Request timeout in seconds (default 3)
- PROXY_NODES_TIMEOUT_SECOND: Alternative request timeout in seconds (default 5)

### HTTP Connection Pool

- MAX_IDLE_CONNS: Max idle HTTP connections (global)
- MAX_IDLE_CONNS_PER_HOST: Max idle HTTP connections per host
- IDLE_CONN_TIMEOUT_SECOND: Idle connection timeout in seconds

### Caching

- CACHE_TTL: Cache time in minutes (for allowed methods)
- CACHEABLE_METHODS: Comma-separated list of RPC methods to be cached, e.g.
- getBlock,getSlot,getBalance

### Health Check

- HEALTH_CHECK_INTERVAL: Interval (minutes) to check node health