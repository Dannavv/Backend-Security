#!/bin/bash

# Log file path
LOG_FILE="docker_history.log"

# Get current date
echo "=== $(date) ===" >> "$LOG_FILE"

# Log current running containers
echo "--- PRE-STARTUP DOCKER PS ---" >> "$LOG_FILE"
if sudo docker ps; then
    sudo docker ps >> "$LOG_FILE"
else
    echo "Error running docker ps" >> "$LOG_FILE"
fi
echo "-----------------------------" >> "$LOG_FILE"

# Check for port conflicts
echo "Checking for port 8080 conflicts..."
CONFLICT_CONTAINER_ID=$(sudo docker ps -q --filter "publish=8080")

if [ -n "$CONFLICT_CONTAINER_ID" ]; then
    echo "Port 8080 is already in use by container(s): $CONFLICT_CONTAINER_ID"
    echo "Stopping conflicting container(s)..."
    sudo docker stop $CONFLICT_CONTAINER_ID > /dev/null
    sudo docker rm $CONFLICT_CONTAINER_ID > /dev/null
    echo "Conflicting container(s) removed."
fi

# Run docker-compose with sudo
echo "Starting services..."
sudo docker-compose up -d --build
