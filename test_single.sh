curl -s -X POST http://localhost:8080/api/get-balances \
-H "Content-Type: application/json" \
-H "X-API-Key: TEST123" \
-d '{"wallets":["A5HNqEzFqR4ub7tTZjgXnanN3xeDka94peYRo8uV2orU"]}' | jq
