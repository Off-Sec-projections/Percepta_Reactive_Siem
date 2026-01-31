#!/bin/bash
# Percepta SIEM Quick Demo Script
# This script demonstrates the complete workflow for the SIEM system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Percepta SIEM - Live Demo Setup${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""

# Step 1: Build the project
echo -e "${YELLOW}[1/7]${NC} Building Percepta SIEM..."
cargo build --release --workspace
echo -e "${GREEN}✓ Build complete${NC}\n"

# Step 2: Clean old data (optional)
read -p "Clean old data directories? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[2/7]${NC} Cleaning old data..."
    rm -rf ~/.local/share/percepta-siem
    rm -rf server/data
    rm -rf server/certs
    echo -e "${GREEN}✓ Data cleaned${NC}\n"
else
    echo -e "${YELLOW}[2/7]${NC} Keeping existing data...\n"
fi

# Step 3: Start the server in background
echo -e "${YELLOW}[3/7]${NC} Starting Percepta SIEM Server..."
cd server

# Kill any existing server
pkill -f percepta-server || true
sleep 2

# Start server in background
../target/release/percepta-server > server.log 2>&1 &
SERVER_PID=$!
echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo -e "   Logs: server/server.log"

# Wait for server to initialize
echo -n "   Waiting for server to initialize"
for i in {1..10}; do
    sleep 1
    echo -n "."
    if grep -q "gRPC server listening" server.log 2>/dev/null; then
        break
    fi
done
echo ""

# Check if server is actually running
if ! ps -p $SERVER_PID > /dev/null; then
    echo -e "${RED}✗ Server failed to start!${NC}"
    echo -e "${RED}Check server/server.log for errors${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Server ready${NC}\n"
sleep 2

# Step 4: Generate OTK for agent enrollment
echo -e "${YELLOW}[4/7]${NC} Generating One-Time Key (OTK) for agent enrollment..."

# Request OTK from server
OTK=$(curl -s -X POST http://localhost:8080/api/enroll/request | jq -r '.otk' 2>/dev/null || echo "")

if [ -z "$OTK" ]; then
    echo -e "${RED}✗ Failed to generate OTK${NC}"
    echo "Trying alternative method..."
    # Alternative: use admin client
    OTK=$(../target/release/admin_client generate-otk 2>/dev/null | grep -oP 'OTK: \K\S+' || echo "")
fi

if [ -z "$OTK" ]; then
    echo -e "${RED}✗ Could not generate OTK. Check if server is running.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ OTK Generated: ${YELLOW}$OTK${NC}\n"

# Step 5: Enroll agent(s)
echo -e "${YELLOW}[5/7]${NC} Enrolling agent..."
cd ..

# Determine platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
    AGENT_CMD="./target/release/percepta-agent"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    PLATFORM="Windows"
    AGENT_CMD="./target/release/percepta-agent.exe"
else
    PLATFORM="Unknown"
    AGENT_CMD="./target/release/percepta-agent"
fi

echo -e "   Platform detected: ${BLUE}$PLATFORM${NC}"

# Enroll the agent
echo -e "   Enrolling agent with OTK..."
$AGENT_CMD --enroll "$OTK" --server http://localhost:8080

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Agent enrolled successfully${NC}\n"
else
    echo -e "${RED}✗ Agent enrollment failed${NC}"
    exit 1
fi

# Step 6: Start the agent
echo -e "${YELLOW}[6/7]${NC} Starting Percepta Agent..."

# Kill any existing agent
pkill -f percepta-agent || true
sleep 1

# Start agent in background
PERCEPTA_SERVER="localhost:50051" $AGENT_CMD > agent.log 2>&1 &
AGENT_PID=$!
echo -e "${GREEN}✓ Agent started (PID: $AGENT_PID)${NC}"
echo -e "   Logs: agent.log"

echo -n "   Waiting for agent to connect"
for i in {1..10}; do
    sleep 1
    echo -n "."
done
echo ""

# Check if agent is running
if ! ps -p $AGENT_PID > /dev/null; then
    echo -e "${RED}✗ Agent failed to start!${NC}"
    echo -e "${RED}Check agent.log for errors${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Agent connected to server${NC}\n"

# Step 7: Display connection info
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Percepta SIEM Demo is Running!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Dashboard:${NC}    http://localhost:8080"
echo -e "${YELLOW}gRPC Server:${NC}  localhost:50051"
echo -e "${YELLOW}Server PID:${NC}   $SERVER_PID"
echo -e "${YELLOW}Agent PID:${NC}    $AGENT_PID"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}What's Happening:${NC}"
echo ""
echo -e "  1. Server is listening on port ${BLUE}50051${NC} (gRPC) and ${BLUE}8080${NC} (HTTP)"
echo -e "  2. Agent is collecting ${GREEN}REAL${NC} system logs:"
if [[ "$PLATFORM" == "Linux" ]]; then
    echo -e "     • ${BLUE}/var/log/auth.log${NC} (authentication events)"
    echo -e "     • ${BLUE}/var/log/syslog${NC} (system events)"
    echo -e "     • ${BLUE}journalctl${NC} (systemd journal)"
else
    echo -e "     • ${BLUE}Windows Event Log${NC} (Security, System, Application)"
fi
echo -e "  3. Events are sent via ${BLUE}gRPC over mTLS${NC}"
echo -e "  4. Server stores events in ${BLUE}SQLite + WAL${NC}"
echo -e "  5. Dashboard shows ${GREEN}live events${NC} via WebSocket"
echo -e "  6. Alerts trigger based on ${BLUE}rules.yaml${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Commands:${NC}"
echo ""
echo -e "  • View server logs:  ${BLUE}tail -f server/server.log${NC}"
echo -e "  • View agent logs:   ${BLUE}tail -f agent.log${NC}"
echo -e "  • Open dashboard:    ${BLUE}xdg-open http://localhost:8080${NC}"
echo -e "  • Stop demo:         ${BLUE}./stop_demo.sh${NC}"
echo -e "  • Kill processes:    ${BLUE}kill $SERVER_PID $AGENT_PID${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Press Ctrl+C to stop tailing logs...${NC}"
echo ""

# Follow both logs
trap "echo -e '\n${YELLOW}Demo still running. Use ./stop_demo.sh to stop.${NC}'; exit 0" INT

echo -e "${BLUE}═══ Server Log ═══${NC}"
tail -f server/server.log &
TAIL1=$!

sleep 2

echo -e "${BLUE}═══ Agent Log ═══${NC}"
tail -f agent.log &
TAIL2=$!

wait $TAIL1 $TAIL2
