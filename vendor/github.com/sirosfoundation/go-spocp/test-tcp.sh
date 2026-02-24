#!/bin/bash
# Integration test for SPOCP TCP server and client

set -e

echo "SPOCP TCP Integration Test"
echo "==========================="
echo ""

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -f spocpd spocp-client
}

trap cleanup EXIT

# Build binaries
echo "Building binaries..."
go build -o spocpd ./cmd/spocpd
go build -o spocp-client ./cmd/spocp-client
echo "✓ Build complete"
echo ""

# Start server in background
echo "Starting server..."
./spocpd -rules ./examples/rules -addr :6001 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "✗ Server failed to start"
    exit 1
fi
echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Test 1: Query that should match (from http.spoc)
echo "Test 1: Query that should match"
RESULT=$(./spocp-client -addr localhost:6001 -query '(4:http(4:page10:index.html)(6:action3:GET)(6:userid4:john))' 2>&1)
if echo "$RESULT" | grep -q "OK"; then
    echo "✓ PASS: Query matched as expected"
else
    echo "✗ FAIL: Query should have matched"
    echo "Output: $RESULT"
    exit 1
fi
echo ""

# Test 2: Query that should NOT match
echo "Test 2: Query that should not match"
RESULT=$(./spocp-client -addr localhost:6001 -query '(4:http(4:page12:unknown.html)(6:action3:GET)(6:userid8:nonexist))' 2>&1)
if echo "$RESULT" | grep -q "DENIED"; then
    echo "✓ PASS: Query denied as expected"
else
    echo "✗ FAIL: Query should have been denied"
    echo "Output: $RESULT"
    exit 1
fi
echo ""

# Test 3: Add a new rule
echo "Test 3: Add a new rule"
RESULT=$(./spocp-client -addr localhost:6001 -add '(4:http(4:page8:test.php)(6:action3:GET)(6:userid4:test))' 2>&1)
if echo "$RESULT" | grep -q "successfully"; then
    echo "✓ PASS: Rule added successfully"
else
    echo "✗ FAIL: Failed to add rule"
    echo "Output: $RESULT"
    exit 1
fi
echo ""

# Test 4: Query the newly added rule
echo "Test 4: Query the newly added rule"
RESULT=$(./spocp-client -addr localhost:6001 -query '(4:http(4:page8:test.php)(6:action3:GET)(6:userid4:test))' 2>&1)
if echo "$RESULT" | grep -q "OK"; then
    echo "✓ PASS: Newly added rule matched"
else
    echo "✗ FAIL: Newly added rule should have matched"
    echo "Output: $RESULT"
    exit 1
fi
echo ""

# Stop server
echo "Stopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""
echo "✓ Server stopped"
echo ""

echo "================================"
echo "All tests passed! ✓"
echo "================================"
