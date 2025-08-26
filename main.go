package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"solana-rpc-proxy/model"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ======== Config ========

// Solana RPC proxy nodes
var proxyNodes []string
var cacheTTL time.Duration
var healthCheck time.Duration
var cacheableMethods map[string]bool

// Define a global HTTP client with tuned settings
var httpClient *http.Client

// Blacklisted nodes (unhealthy state)
var blacklist = make(map[string]bool)
var blacklistLock sync.RWMutex

// Redis client
var rdb *redis.Client
var ctx = context.Background()

func initConfig() {
	nodes := getEnv("PROXY_NODES", "")
	if nodes == "" {
		log.Fatal("No proxy nodes provided, please set PROXY_NODES env")
	}
	proxyNodes = strings.Split(nodes, ",")

	ttlStr := getEnv("CACHE_TTL", "60")
	ttl, err := strconv.Atoi(ttlStr)
	if err != nil {
		ttl = 60
	}
	cacheTTL = time.Duration(ttl) * time.Minute

	hcStr := getEnv("HEALTH_CHECK_INTERVAL", "30")
	hc, err := strconv.Atoi(hcStr)
	if err != nil {
		hc = 30
	}
	healthCheck = time.Duration(hc) * time.Minute

	methods := getEnv("CACHEABLE_METHODS", "getBlock,getSlot")
	cacheableMethods = make(map[string]bool)
	for _, m := range strings.Split(methods, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			cacheableMethods[m] = true
		}
	}

	timeout, err := strconv.Atoi(getEnv("PROXY_NODES_TIMEOUT_SECOND", "5"))
	if err != nil {
		panic(err)
	}
	maxIdleConns, err := strconv.Atoi(getEnv("MAX_IDLE_CONNS", "1000000"))
	if err != nil {
		panic(err)
	}
	maxIdleConnsPerHost, err := strconv.Atoi(getEnv("MAX_IDLE_CONNS_PER_HOST", "10000"))
	if err != nil {
		panic(err)
	}
	idleConnTimeout, err := strconv.Atoi(getEnv("IDLE_CONN_TIMEOUT_SECOND", "90"))
	if err != nil {
		panic(err)
	}
	httpClient = &http.Client{
		Timeout: time.Duration(timeout) * time.Second, // request timeout
		Transport: &http.Transport{
			MaxIdleConns:        maxIdleConns,                                 // allow many idle connections
			MaxIdleConnsPerHost: maxIdleConnsPerHost,                          // per-host idle connections
			IdleConnTimeout:     time.Duration(idleConnTimeout) * time.Second, // idle connection lifetime
		},
	}

	log.Printf("Config loaded: Nodes=%v, CacheTTL=%v, HealthCheck=%v, CacheableMethods=%v, httpClient={timeout:%v, maxIdleConns:%v, maxIdleConnsPerHost:%v, idleConnTimeout:%v}",
		proxyNodes, cacheTTL, healthCheck, cacheableMethods, timeout, maxIdleConns, maxIdleConnsPerHost, idleConnTimeout)
}

func main() {
	initConfig()

	// Initialize Redis client
	rdb = redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "127.0.0.1:6379"),
		Password: getEnv("REDIS_PASSWORD", "123456"),
		DB:       0,
	})
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Start health check routine
	go healthCheckLoop()

	// Start HTTP server
	http.HandleFunc("/", handleRPC)
	log.Println("Solana RPC Proxy with selective Redis cache running at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func handleRPC(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	if len(body) == 0 {
		http.Error(w, "Empty body", http.StatusBadRequest)
		return
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		http.Error(w, "Empty body", http.StatusBadRequest)
		return
	}

	var finalResp []byte
	var err error

	if trimmed[0] == '{' {
		var id interface{}
		finalResp, id, err = processSingleRequest(body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write(errResponseRaw(id, err))
			return
		}
	} else if trimmed[0] == '[' {
		var requests []json.RawMessage
		if err := json.Unmarshal(body, &requests); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write(errResponseRaw("", err))
			return
		}

		responses := make([]json.RawMessage, 0, len(requests))
		for _, raw := range requests {
			resp, id, err := processSingleRequest(raw)
			if err != nil {
				responses = append(responses, errResponseRaw(id, err))
			} else {
				responses = append(responses, resp)
			}
		}
		finalResp, _ = json.Marshal(responses)
	} else {
		http.Error(w, "Invalid JSON-RPC body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(finalResp)
}

func processSingleRequest(body []byte) ([]byte, interface{}, error) {
	var req model.RpcRequest
	err := json.Unmarshal(body, &req)
	if err != nil {
		return nil, "", err
	}

	shouldCache := cacheableMethods[req.Method]
	cacheKey := ""
	if shouldCache {
		cacheKey = hashRequest(req)
		if data, err := rdb.Get(ctx, cacheKey).Bytes(); err == nil {
			return data, "", nil
		}
	}

	var resp []byte
	for _, node := range proxyNodes {
		if isBlacklisted(node) {
			continue
		}
		resp, err = forwardRequest(node, body)
		if err == nil {
			break
		} else {
			log.Printf("Node %s failed: %v", node, err)
		}
	}

	if err != nil {
		return nil, req.ID, err
	}

	if shouldCache {
		if err := rdb.Set(ctx, cacheKey, resp, cacheTTL).Err(); err != nil {
			log.Printf("Failed to write cache: %v", err)
		}
	}
	return resp, "", nil
}

func errResponseRaw(id interface{}, err error) []byte {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32000,
			"message": err.Error(),
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// Forward request to Solana RPC node
func forwardRequest(node string, body []byte) ([]byte, error) {
	log.Printf("Forwarding request to %s, body: %s", node, body)
	req, err := http.NewRequest("POST", node, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp model.JSONRPCResponse
	if err := json.Unmarshal(respBytes, &rpcResp); err == nil {
		if rpcResp.Error != nil {
			return nil, fmt.Errorf("JSON-RPC error [%d]: %s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
	}

	return respBytes, nil
}

// Compute hash for method + params
func hashRequest(req model.RpcRequest) string {
	var hashData []interface{}
	switch req.Method {
	case "getBlock":
		block := req.Params.([]interface{})[0]
		config := req.Params.([]interface{})[1].(map[string]interface{})
		if v, ok := config["encoding"]; ok && v == "json" {
			delete(config, "encoding")
		}
		hashData = append(hashData, req.Method, block, config)
	default:
		hashData = append(hashData, req.Method, req.Params)
	}
	b, _ := json.Marshal(hashData)
	h := sha256.Sum256(b)
	return "solana_cache:" + hex.EncodeToString(h[:])
}

// Blacklist operations
func isBlacklisted(node string) bool {
	blacklistLock.RLock()
	defer blacklistLock.RUnlock()
	return blacklist[node]
}

func addToBlacklist(node string) {
	blacklistLock.Lock()
	defer blacklistLock.Unlock()
	blacklist[node] = true
}

func removeFromBlacklist(node string) {
	blacklistLock.Lock()
	defer blacklistLock.Unlock()
	delete(blacklist, node)
}

// Periodic health check
func healthCheckLoop() {
	ticker := time.NewTicker(healthCheck)
	defer ticker.Stop()

	for range ticker.C {
		for _, node := range proxyNodes {
			// Check if a previously unhealthy node has recovered
			if checkNodeAlive(node) {
				log.Printf("Node %s recovered", node)
				removeFromBlacklist(node)
			} else {
				if !isBlacklisted(node) {
					log.Printf("Node %s is unhealthy", node)
					addToBlacklist(node)
				}
			}
		}
	}
}

// Check node availability using getHealth RPC
func checkNodeAlive(node string) bool {
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"getHealth"}`)
	resp, err := http.Post(node, "application/json", bytes.NewReader(req))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
