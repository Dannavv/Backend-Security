#!/bin/bash

# Configuration
PROJECT_NAME="unified-secure-gateway"
DOCKER_COMPOSE_COMMAND="docker-compose"

echo "🚀 Starting $PROJECT_NAME..."

# Ensure directories exist and have correct permissions
mkdir -p logs quarantine uploads
chmod -R 777 logs quarantine uploads

# Stop existing containers
echo "🛑 Stopping existing containers..."
$DOCKER_COMPOSE_COMMAND down -v

# Build and start containers
echo "🛠️ Building and starting containers..."
$DOCKER_COMPOSE_COMMAND up --build -d

echo "✅ $PROJECT_NAME is running!"
echo "📍 Access the UI at: http://localhost:8085"
echo "📜 View logs with: $DOCKER_COMPOSE_COMMAND logs -f"
