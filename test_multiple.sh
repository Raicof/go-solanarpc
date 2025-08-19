response=$(curl -X POST http://localhost:8080/api/get-balance \
-H "Content-Type: application/json" \
-H "X-API-Key: TEST123" \
-d '{"wallets":["A5HNqEzFqR4ub7tTZjgXnanN3xeDka94peYRo8uV2orU",
"MJKqp326RZCHnAAbew9MDdui3iCKWco7fsK9sVuZTX2",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"8PjJTv657aeN9p5R2WoM6pPSz385chvTTytUWaEjSjkq",
"3bHbMa5VW3np5AJazuacidrN4xPZgwhcXigmjwHmBg5e"]}')

if echo "$response" | jq . >/dev/null 2>&1; then
  echo "$response" | jq .
else
  echo "Raw response:"
  echo "$response"
fi
