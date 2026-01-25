#!/bin/bash

# --- Military-Grade Logging Startup Script ---

echo "🚀 Initializing ERP Logging Stack..."

# 1. Create necessary directories
echo "📁 Creating log directories..."
mkdir -p logs/mysql logs/apache
touch logs/app.log logs/security.log logs/audit.log logs/performance.log
touch logs/apache/erp_access.log logs/mysql/slow.log
chmod -R 777 logs  # Ensure Docker and PHP can write/truncate these

# 2. Cleanup old runs
echo "🧹 Cleaning up old containers..."
docker-compose down -v --remove-orphans

# 3. Build and launch
echo "🏗️ Building and launching containers..."
docker-compose up --build -d

# 4. Success message
echo "✅ System is UP!"
echo "🌐 Dashboard: http://localhost:8086"
echo "📂 Project Logs: $(pwd)/logs"
echo "🐘 PHP Logs: $(pwd)/logs/app.log"
echo "🛢️ MySQL Logs: $(pwd)/logs/mysql/error.log"

# Show container status
docker ps | grep erp_
