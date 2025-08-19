response=$(curl -X POST http://localhost:8080/api/get-balance \
-H "Content-Type: application/json" \
-H "X-API-Key: TEST123" \
-d '{"wallets":["A5HNqEzFqR4ub7tTZjgXnanN3xeDka94peYRo8uV2orU"]}')

if echo "$response" | jq . >/dev/null 2>&1; then
  echo "$response" | jq .
else
  echo "Raw response:"
  echo "$response"
fi
