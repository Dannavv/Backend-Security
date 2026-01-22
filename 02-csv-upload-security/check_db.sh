#!/bin/bash

# Configuration
DB_CONTAINER="csv-security-mysql"
DB_USER="csv_user"
DB_PASS="csv_secure_pass_2024"
DB_NAME="csv_security"

# Colors for better UI
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

function show_header() {
    clear
    echo -e "${BLUE}=======================================${NC}"
    echo -e "${BLUE}   📊 CSV Security Database Explorer   ${NC}"
    echo -e "${BLUE}=======================================${NC}"
}

function list_tables() {
    echo -e "${YELLOW}Existing Tables and Row Counts:${NC}"
    # Get tables and their row count + size
    docker exec -it "$DB_CONTAINER" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
    SELECT 
        table_name AS 'Table', 
        table_rows AS 'Approx Rows',
        ROUND((data_length + index_length) / 1024, 2) AS 'Size (KB)'
    FROM information_schema.tables 
    WHERE table_schema = '$DB_NAME';"
}

while true; do
    show_header
    list_tables
    
    echo -e "\n${YELLOW}Usage Details:${NC}"
    echo "1. csv_imports: Final storage for clean, validated records."
    echo "2. csv_staging: Temporary storage used during atomic transactions."
    echo "3. upload_audit: Forensic trail of all upload attempts and security results."
    echo "4. rate_limits: Tracks IP and Session activity to prevent DoS."

    echo -e "\n${GREEN}Options:${NC}"
    echo -e "Enter ${BLUE}1-4${NC} or ${BLUE}table name${NC} to view its content or ${RED}'q'${NC} to quit."
    read -p "Select action: " choice

    if [[ "$choice" == "q" ]]; then
        echo "Exiting..."
        exit 0
    fi

    # Map numbers to table names
    case $choice in
        1) table="csv_imports" ;;
        2) table="csv_staging" ;;
        3) table="upload_audit" ;;
        4) table="rate_limits" ;;
        *) table="$choice" ;;
    esac

    # Check if table exists (silently) before trying to select
    TABLE_EXISTS=$(docker exec "$DB_CONTAINER" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -Nse "SHOW TABLES LIKE '$table';")

    if [[ -z "$TABLE_EXISTS" ]]; then
        echo -e "\n${RED}Error: Table '$table' not found.${NC}"
    else
        echo -e "\n${BLUE}--- Content of table: $table (Top 20 rows) ---${NC}"
        docker exec -it "$DB_CONTAINER" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "SELECT * FROM \`$table\` LIMIT 20;"
    fi
    
    echo -e "\n${YELLOW}Press enter to return to menu...${NC}"
    read
done
