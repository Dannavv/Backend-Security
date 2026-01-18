#!/bin/bash

# Configuration
DB_USER="root"
DB_PASS="rootpassword"
DB_NAME="testdb"

echo "=========================================="
echo "    CHECKING DATABASE: $DB_NAME"
echo "=========================================="

echo "[1] LISTING TABLES:"
# We use docker-compose exec to run the mysql client inside the db container
sudo docker-compose exec -T db mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "SHOW TABLES;"

echo ""
echo "[2] CHECKING TABLE CONTENTS (Last 5 Records):"

# Helper function to query a table securely
check_types() {
    local table_name=$1
    # Check if table exists query
    local exists=$(sudo docker-compose exec -T db mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -sse "SHOW TABLES LIKE '$table_name';")
    
    if [[ -n "$exists" ]]; then
        echo "--> Table: $table_name"
        sudo docker-compose exec -T db mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "SELECT * FROM $table_name ORDER BY id DESC LIMIT 5;"
    else
        echo "--> Table: $table_name (NOT FOUND - Open the forms in browser to create tables)"
    fi
    echo "------------------------------------------"
}

check_types "users"
check_types "products"
check_types "feedback"
