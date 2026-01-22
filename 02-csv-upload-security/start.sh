#!/bin/bash

# CSV Upload Security - Quick Start Script
# ==========================================

set -e

echo "🔐 CSV Upload Security Module"
echo "=============================="
echo ""

# Create required directories
echo "📁 Creating directories..."
mkdir -p quarantine/uploads
mkdir -p logs
chmod -R 777 quarantine
chmod -R 777 logs

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
sudo docker-compose down 2>/dev/null || true

# Build and start containers
echo "🚀 Building and starting containers..."
sudo docker-compose up -d --build

# Wait for MySQL to be ready
echo "⏳ Waiting for MySQL to be ready..."
sleep 5

# Check container status
echo ""
echo "📊 Container Status:"
sudo docker-compose ps

echo ""
echo "✅ Setup complete!"
echo ""
echo "🌐 Access points:"
echo "   • Web UI:      http://localhost:8082"
echo "   • phpMyAdmin:  http://localhost:8083"
echo ""
echo "📖 Test the security features:"
echo "   1. Upload a valid CSV file"
echo "   2. Try uploading test/malicious_samples/* files"
echo "   3. Check the audit log at /history"
echo ""
echo "🔧 Useful commands:"
echo "   • View logs:    sudo docker-compose logs -f"
echo "   • Stop:         sudo docker-compose down"
echo "   • Rebuild:      sudo docker-compose up -d --build"
echo ""
