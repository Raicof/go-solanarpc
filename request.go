package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
	"os"
	"io"
	"log"
	"sort"
	"sync"
	"strings"

	"go.mongodb.org/mongo-driver/mongo/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/davecgh/go-spew/spew"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// ---- constants

const (
	TTL     = 10 * time.Second
	srvAddr = ":52052"
)

// ---- start structures

type GetBalanceRequest struct {
	Wallets []string `json:"wallets"`
}

type WalletBalance struct {
	Wallet   string  `json:"wallet"`
	Lamports uint64  `json:"lamports"`
	SOL      float64 `json:"sol"`
	Cached   bool    `json:"cached"`
	Source   string  `json:"source"`
}

type GetBalanceRequest struct {
	Balances []WalletBalance `json:"balances"`
}

// ---- API

var (
	mongoClient *mongo.client
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
	_, _ = apiKeysColl.indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:		bson.D{{Key: "key", Value: 1}},
		Options: 	options.Index().SetUnique(true),
	})
	return nil

}

// do----> Validations

func validApiKey (ctx context.Context, key string) (bool, error) {
	if key == ""
}


// do----> AuthHandler
// do----> Hashing??
// do----> Optim RateLimit 
// do----> Cache
// do----> Solana RPC
// do----> Requests HTTP




func main() {
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
