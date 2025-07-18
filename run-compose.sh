#!/bin/bash

# Docker Compose profile helper script
# This script helps you easily run different sets of services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
show_usage() {
    echo -e "${BLUE}Docker Compose Profile Helper${NC}"
    echo
    echo "Usage: $0 [MODE] [DOCKER_COMPOSE_ARGS...]"
    echo
    echo -e "${GREEN}Available modes:${NC}"
    echo "  test       - Run only test containers (openbao-test, blockchain-api-test)"
    echo "  production - Run only production containers (athena, ub, bsc + their openbao)"
    echo "  all        - Run all containers"
    echo "  status     - Show status of all containers"
    echo "  stop       - Stop all containers"
    echo "  clean      - Stop and remove all containers and volumes"
    echo
    echo -e "${GREEN}Examples:${NC}"
    echo "  $0 test                    # Start test containers"
    echo "  $0 production              # Start production containers"
    echo "  $0 all                     # Start all containers"
    echo "  $0 test -d                 # Start test containers in detached mode"
    echo "  $0 production --build      # Start production containers and rebuild images"
    echo "  $0 status                  # Show container status"
    echo "  $0 stop                    # Stop all containers"
    echo "  $0 clean                   # Clean up everything"
    echo
    echo -e "${YELLOW}Note:${NC} Additional docker-compose arguments can be passed after the mode."
}

# Function to run docker-compose with profile
run_compose() {
    local profile="$1"
    shift
    local args="$@"
    
    echo -e "${BLUE}Running Docker Compose with profile: ${GREEN}$profile${NC}"
    echo -e "${BLUE}Command: ${NC}docker-compose --profile $profile up $args"
    echo
    
    docker-compose --profile "$profile" up $args
}

# Function to show container status
show_status() {
    echo -e "${BLUE}Container Status:${NC}"
    echo
    docker-compose ps
    echo
    echo -e "${BLUE}Profile Information:${NC}"
    echo -e "${GREEN}Test containers:${NC}"
    echo "  - openbao-test (port 8203)"
    echo "  - blockchain-api-test (port 3003)"
    echo
    echo -e "${GREEN}Production containers:${NC}"
    echo "  - openbao-athena (port 8200) + blockchain-api-athena (port 3000)"
    echo "  - openbao-ub (port 8201) + blockchain-api-ub (port 3001)"
    echo "  - openbao-bsc (port 8202) + blockchain-api-bsc (port 3002)"
}

# Function to stop all containers
stop_all() {
    echo -e "${YELLOW}Stopping all containers...${NC}"
    docker-compose down
    echo -e "${GREEN}All containers stopped.${NC}"
}

# Function to clean up everything
clean_all() {
    echo -e "${YELLOW}Cleaning up all containers and volumes...${NC}"
    docker-compose down -v --remove-orphans
    echo -e "${GREEN}Cleanup complete.${NC}"
}

# Main logic
if [ $# -eq 0 ]; then
    show_usage
    exit 1
fi

MODE="$1"
shift

case "$MODE" in
    "test")
        run_compose "test" "$@"
        ;;
    "distributed")
        run_compose "distributed" "$@"
        ;;
    "all")
        run_compose "all" "$@"
        ;;
    "status")
        show_status
        ;;
    "stop")
        stop_all
        ;;
    "clean")
        clean_all
        ;;
    "-h"|"--help"|"help")
        show_usage
        ;;
    *)
        echo -e "${RED}Error: Unknown mode '$MODE'${NC}"
        echo
        show_usage
        exit 1
        ;;
esac
