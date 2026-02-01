#!/usr/bin/env bash

NUM_PORTS=20 # how many ports to open
PORT_MIN=20000
PORT_MAX=60000

PIDS=()
PORTS=()

cleanup() {
  echo
  echo "[*] Cleaning up listeners..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null
  done
  exit 0
}

trap cleanup INT TERM

echo "[*] Opening $NUM_PORTS random TCP ports..."

while [ "${#PORTS[@]}" -lt "$NUM_PORTS" ]; do
  port=$((RANDOM % (PORT_MAX - PORT_MIN + 1) + PORT_MIN))

  # avoid duplicates
  if [[ " ${PORTS[*]} " == *" $port "* ]]; then
    continue
  fi

  # start listener
  nc -lk -p "$port" >/dev/null 2>&1 &
  pid=$!

  # give it a moment to fail if port is taken
  sleep 0.05
  if kill -0 "$pid" 2>/dev/null; then
    PORTS+=("$port")
    PIDS+=("$pid")
    echo "  [+] Listening on TCP port $port"
  fi
done

echo
echo "[*] All listeners up."
echo "[*] Press Ctrl-C to stop."
# keep script alive
while true; do sleep 1; done
