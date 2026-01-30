#!/bin/bash
# Stop Percepta SIEM Demo

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Stopping Percepta SIEM Demo...${NC}"

# Kill server
echo -n "Stopping server... "
pkill -f percepta-server && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}(not running)${NC}"

# Kill agent
echo -n "Stopping agent... "
pkill -f percepta-agent && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}(not running)${NC}"

# Kill any tail processes
pkill -f "tail -f.*log" 2>/dev/null

echo -e "${GREEN}Demo stopped${NC}"
