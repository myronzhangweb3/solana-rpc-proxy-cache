package model

import "encoding/json"

// JSON-RPC request structure
type RpcRequest struct {
	ID      interface{} `json:"id"`
	Jsonrpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type JSONRPCResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	ID      string          `json:"id"`
}
