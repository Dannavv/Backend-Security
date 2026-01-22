#!/bin/bash

# 🛡️ PDF Security Lab Startup Script

echo "🚀 Initializing PDF Security Module..."

# 1. Ensure directories exist and have correct permissions
mkdir -p quarantine logs
sudo chown -R $USER:$USER quarantine logs
chmod -R 777 quarantine logs # For local dev simplicity, Docker will use more restrictive ones internaly

# 2. Shutdown existing containers if any
docker-compose down -v --remove-orphans

# 3. Build and Start
echo "📦 Building and starting containers..."
docker-compose up --build -d

# 4. Wait for MySQL
echo "⏳ Waiting for Database to be ready..."
until docker exec pdf_security_db mysqladmin ping -h "localhost" --silent; do
    printf "."
    sleep 2
done

echo -e "\n✅ System is UP!"
echo "--------------------------------------------------"
echo "🌐 Portal: http://localhost:8084"
echo "📜 Logs: ./logs"
echo "📂 Quarantine: ./quarantine"
echo "--------------------------------------------------"
echo "Keep this terminal open or run 'docker-compose logs -f' to see real-time security events."
