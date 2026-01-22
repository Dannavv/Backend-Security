#!/bin/bash

# 🚀 Start Script for Image Security Chapter

# 1. Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Starting Image Security Environment (Chapter 04)...${NC}"

# 2. Check for existing containers and stop them
echo -e "${BLUE}Stopping existing containers...${NC}"
sudo docker-compose down -v

# 3. Create host directories with correct permissions if they don't exist
echo -e "${BLUE}Preparing host directories...${NC}"
mkdir -p logs quarantine src/uploads
chmod -R 777 logs quarantine src/uploads

# 4. Build and start
echo -e "${BLUE}Building and launching containers...${NC}"
sudo docker-compose up --build -d

# 5. Wait for MySQL to be ready
echo -e "${BLUE}Waiting for database initialization...${NC}"
sleep 5

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}  Image Security Portal is live at: http://localhost:8085 ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "${BLUE}Logs can be monitored in the ./logs directory.${NC}"
