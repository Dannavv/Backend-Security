#!/bin/bash
# Chapter 7: Military-Grade Secure Query - Launcher Script

set -e

echo "🛡️  Chapter 7: Military-Grade Secure Query Function"
echo "=================================================="

# Check for running containers on port 8087
if lsof -Pi :8087 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 8087 in use. Stopping existing containers..."
    docker-compose down 2>/dev/null || true
fi

# Build and start
echo "🔨 Building containers..."
docker-compose build --no-cache

echo "🚀 Starting services..."
docker-compose up -d

# Wait for MySQL
echo "⏳ Waiting for MySQL to be ready..."
sleep 5

echo ""
echo "✅ Ready!"
echo "📍 Dashboard: http://localhost:8087"
echo "📝 Logs: ./logs/security.log"
echo ""
echo "Run tests with:"
echo "  docker exec -it ch7-secure-query php test_secure_query.php"
