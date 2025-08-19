//	TESTS
//
// The rest API working with 1 wallet. -- WORKS
// The rest API working with multiple wallets. -- WORKS
// The rest API working with 5 requests using the same wallet. -- WORKS
// The rest API working with all of the above at the same time. -- WORKS
// The rest API working with IP rate limiting. -- Further checks
// The rest API working with caching. -- Further checks
// Testing authentication and rate limiting. -- Further checks
// OPTIMIZE
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// ---- constants

const (
	TTL               = 10 * time.Second
	defaultServerAddr = ":8080"
	maxBodyBytes      = 1 << 20
)

// ---- start structures

type GetBalanceResponse struct {
	Balances []WalletBalance `json:"balances"`
}

type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	r        rate.Limit
	b        int
}

type cacheEntry struct {
	lamports  uint64
	expiresAt time.Time
}

type rpcBalanceBody struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Value uint64 `json:"value"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ---- API

var (
	mongoClient *mongo.Client
	apiKeysColl *mongo.Collection
)

// do----> Start Mongo

func initMongo(ctx context.Context) error {
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		return errors.New("Set URI")
	}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil || client.Ping(ctx, nil) != nil {
		return err
	}

	mongoClient = client
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "ifra_trial"
	}

	collName := os.Getenv("MONGO_COLL")
	if collName == "" {
		collName = "api_keys"
	}

	apiKeysColl = client.Database(dbName).Collection(collName)
	_, _ = apiKeysColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "key", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return nil

}

// do----> Validations

func validateApiKey(ctx context.Context, key string) (bool, error) {

	if key == "" {
		return false, nil
	}
	var doc struct {
		key    string `bson:"key"`
		Active bool   `bson:"active"`
	}
	err := apiKeysColl.FindOne(ctx, bson.M{"key": key, "active": true}).Decode(&doc)

	if err == mongo.ErrNoDocuments {
		return false, nil
	}

	return err == nil && doc.Active, err

}

// do----> AuthHandler
// do----> Hashing??
// do----> Optim RateLimit

func rateIPLimit(r rate.Limit, b int) *ipRateLimiter {

	return &ipRateLimiter{limiters: make(map[string]*rate.Limiter), r: r, b: b}

}

func (i *ipRateLimiter) getLimiter(ip string) *rate.Limiter {

	i.mu.Lock()
	defer i.mu.Unlock()
	lim, exists := i.limiters[ip]

	if !exists {
		lim = rate.NewLimiter(i.r, i.b)
		i.limiters[ip] = lim
	}

	return lim
}

// do----> Cache

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)
	sf      singleflight.Group
)

func getFromCache(wallet string) (uint64, bool) {
	now := time.Now()
	cacheMu.RLock()
	ent, ok := cache[wallet]
	cacheMu.RUnlock()
	if ok && now.Before(ent.expiresAt) {
		return ent.lamports, true
	}
	return 0, false
}

func setCache(wallet string, lamports uint64) {
	cacheMu.Lock()
	cache[wallet] = cacheEntry{lamports: lamports, expiresAt: time.Now().Add(TTL)}
	cacheMu.Unlock()
}

// do----> Solana RPC

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  *rpcBalanceBody `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// do----> Requests HTTP

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
	},
}

// do -----> fetch Balance from wallet

func fetchBalanceRPC(ctx context.Context, wallet string) (uint64, error) {
	rpcURL := os.Getenv("HELIUS_RPC_URL")
	if rpcURL == "" {
		return 0, errors.New("HELIUS_RPC_URL NOT SET")
	}

	payload := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getBalance",
		Params:  []interface{}{wallet},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, strings.NewReader(string(body)))

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("rpc status %d: %s", resp.StatusCode, string(b))
	}

	var rr rpcResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))

	if err := dec.Decode(&rr); err != nil {
		return 0, err
	}

	if err != nil {
		return 0, err
	}
	if rr.Error != nil {
		return 0, fmt.Errorf("RPC error %d: %s", rr.Error.Code, rr.Error.Message)
	}
	if rr.Result == nil {
		return 0, errors.New("no result - RPC")
	}
	return rr.Result.Value, nil
}

//--- balance cache

func getBalanceCached(ctx context.Context, wallet string) (uint64, bool, error) {
	if val, ok := getFromCache(wallet); ok {
		return val, true, nil
	}
	v, err, _ := sf.Do(wallet, func() (interface{}, error) {
		if val, ok := getFromCache(wallet); ok {
			return val, nil
		}
		lam, e := fetchBalanceRPC(ctx, wallet)
		if e != nil {
			return uint64(0), e
		}
		setCache(wallet, lam)
		return lam, nil
	})
	if err != nil {
		return 0, false, err
	}
	return v.(uint64), false, nil
}

//--- IP client

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	log.Printf("Client IP: %s", r.RemoteAddr)
	return r.RemoteAddr
}

// --- clean cache
func handleClearCache(w http.ResponseWriter, r *http.Request) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cache = make(map[string]cacheEntry)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cache cleared"})
	return
}

//--- build JSON

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// do---> RateLimit on auth

func authAndRateLimit(limiter *ipRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "apikey ") {
				apiKey = strings.TrimSpace(auth[len("apikey "):])
			}
		}
		ok, err := validateApiKey(ctx, apiKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth check fail"})
			return
		}

		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		}

		ip := getClientIP(r)
		lim := limiter.getLimiter(ip)
		if !lim.Allow() {
			w.Header().Set("Retry-After", "6")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// do ---> workBalance

type WalletBalance struct {
	Wallet   string  `json:"wallet"`
	Lamports uint64  `json:"lamports"`
	SOL      float64 `json:"sol"`
	Cached   bool    `json:"cached"`
	Source   string  `json:"source"`
}

type GetBalanceRequest struct {
	Wallets []string `json:"wallets"`
}

func handleGetBalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()

	var req GetBalanceRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	unique := make([]string, 0, len(req.Wallets))
	seen := make(map[string]struct{}, len(req.Wallets))
	for _, wlt := range req.Wallets {
		w := strings.TrimSpace(wlt)
		if _, ok := seen[w]; !ok {
			seen[w] = struct{}{}
			unique = append(unique, w)
		}
	}

	if len(unique) == 0 {
		log.Printf("wallets len=%d, payload=%v", len(req.Wallets), req.Wallets)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid wallet addresses"})
		return
	}

	type result struct {
		wallet   string
		lamports uint64
		cached   bool
		err      error
	}

	resCh := make(chan result, len(unique))
	var wg sync.WaitGroup
	for _, wallet := range unique {
		wg.Add(1)
		go func(wlt string) {
			defer wg.Done()
			lam, cached, err := getBalanceCached(r.Context(), wlt)
			resCh <- result{wallet: wlt, lamports: lam, cached: cached, err: err}
		}(wallet)
	}
	wg.Wait()
	close(resCh)

	vals := make(map[string]result, len(unique))
	for r := range resCh {
		vals[r.wallet] = r
	}

	resp := GetBalanceResponse{Balances: make([]WalletBalance, 0, len(req.Wallets))}
	for _, wlt := range req.Wallets {
		w := strings.TrimSpace(wlt)
		if w == "" {
			continue
		}
		if v, ok := vals[w]; ok {
			if v.err != nil {
				resp.Balances = append(resp.Balances, WalletBalance{Wallet: w, Lamports: 0, SOL: 0, Cached: false, Source: "error"})
				continue
			}
			sol := float64(v.lamports) / 1_000_000_000.0
			src := "rpc"
			if v.cached {
				src = "cache"
			}
			resp.Balances = append(resp.Balances, WalletBalance{Wallet: w, Lamports: v.lamports, SOL: sol, Cached: v.cached, Source: src})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := initMongo(ctx); err != nil {
		log.Fatalf("mongo init failed: %v", err)
	}

	limiter := rateIPLimit(rate.Every(time.Minute/10), 10)

	mux := http.NewServeMux()
	mux.Handle("/api/get-balance", authAndRateLimit(limiter, http.HandlerFunc(handleGetBalance)))
	mux.Handle("/api/clear-cache", authAndRateLimit(limiter, http.HandlerFunc(handleClearCache)))

	srv := &http.Server{
		Addr:         defaultServerAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("listening on %s", defaultServerAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}

	endpoint := rpc.MainNetBeta_RPC
	client := rpc.New(endpoint)

	pubKey := solana.MustPublicKeyFromBase58("7xLk17EQQ5KLDLDe44wCmupJKJjTGd8hs3eSVVhCx932")
	out, err := client.GetBalance(
		context.TODO(),
		pubKey,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		panic(err)
	}
	spew.Dump(out)
	spew.Dump(out.Value) // total lamports on the account; 1 sol = 1000000000 lamports

	var lamportsOnAccount = new(big.Float).SetUint64(uint64(out.Value))
	// Convert lamports to sol:
	var solBalance = new(big.Float).Quo(lamportsOnAccount, new(big.Float).SetUint64(solana.LAMPORTS_PER_SOL))

	// WARNING: this is not a precise conversion.
	fmt.Println("◎", solBalance.Text('f', 10))
}
