response=$(curl -X POST http://localhost:8080/api/get-balance \
-H "Content-Type: application/json" \
-H "X-API-Key: TEST123" \
-d '{"wallets":["9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3",
"9uRJ5aGgeu2i3J98hsC5FDxd2PmRjVy9fQwNAy7fzLG3"]}')

if echo "$response" | jq . >/dev/null 2>&1; then
  echo "$response" | jq .
else
  echo "Raw response:"
  echo "$response"
fi
