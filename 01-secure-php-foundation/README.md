# Chapter 01: Secure PHP Foundation

A secure, Dockerized PHP + MySQL environment demonstrating procedural PHP form handling, input validation, and secure setups without frameworks, classes, or PDO.

## Features

- **Dockerized Environment**: Full LAMP stack (Linux, Apache, MySQL, PHP) using Docker Compose.
- **Smart Wrapper Script**: `start.sh` script that enforces strict logging and automatically handles port 8080 conflicts by stopping/removing old containers.
- **Procedural PHP**: Pure procedural PHP implementation (no Classes, no PDO).
- **Centralized Validation**: Robust input validation system defined in a configuration file and processed by a functional validator.
- **Modern UI**: Clean, dark-mode styling using pure CSS.
- **Zero-Information Leakage**: Application errors are logged server-side, while users see generic messages to prevent exposing system details.
- **Hardened HTTP Headers**: Implements `X-Frame-Options`, `Content-Security-Policy`, and other headers to mitigate Clickjacking and XSS.
- **Full-Spectrum Validation**: Beyond format checks, inputs are sanitized (Null-Byte stripping) and checked for strict numeric types.
- **Database Hardening**: Enforces `utf8mb4` charset and `STRICT_ALL_TABLES` SQL mode to prevent encoding attacks and data truncation.

## Project Structure

```
├── Dockerfile              # PHP-Apache configuration with MySQLi extension
├── docker-compose.yml      # Service orchestration (PHP & MySQL)
├── start.sh                # Wrapper script for starting services securely
├── check_db.sh             # Utility script to inspect database tables/records
├── docker_history.log      # Log file for container history verification
└── src/
    ├── form1.php           # User Registration Form (Secured)
    ├── form2.php           # Product Entry Form (Secured)
    ├── form3.php           # System Feedback Form (Secured)
    ├── index.php           # Database connection test
    ├── rules.php           # Validation rules configuration
    ├── security.php        # HTTP headers & security configuration
    ├── security_status.php # Security badge component
    ├── style.css           # Shared styling
    └── validator.php       # Core validation logic (procedural)
```

## Setup & Running

1. **Start the Environment**
   Run the wrapper script to log current state, handle port conflicts, and start containers.
   ```bash
   chmod +x start.sh
   ./start.sh
   ```

2. **Access the Application**
   Open your browser to:
   - **Registration**: [http://localhost:8080/form1.php](http://localhost:8080/form1.php)
   - **Products**: [http://localhost:8080/form2.php](http://localhost:8080/form2.php)
   - **Feedback**: [http://localhost:8080/form3.php](http://localhost:8080/form3.php)
   - **DB Check**: [http://localhost:8080/index.php](http://localhost:8080/index.php)

3. **Verify Database (Optional)**
   Use the utility script to inspect database tables and recent records without logging into the container manually.
   ```bash
   chmod +x check_db.sh
   ./check_db.sh
   ```

## Technical Implementation

### Validation System
Validation rules are defined in `src/rules.php` as a configuration array. The `src/validator.php` file contains a purely functional `validate_input()` function that checks data against these rules.

**Supported Validation Rules:**
- `required`: Field must not be empty.
- `min_length`: Minimum string length.
- `max_length`: Maximum string length.
- `type`: Specific type checks (`email`, `numeric`).
- `pattern`: Regex pattern matching (e.g., for alphanumeric, password complexity).
- `allowed_values`: Enum-like validation for select inputs.

### Security Layers
- **Database**: 
    - Uses `mysqli` prepared statements to prevent SQL Injection.
    - Connection enforces `utf8mb4` to block character-set bypasses.
    - Session uses `STRICT_ALL_TABLES` to prevent malicious data truncation.
- **Input Hygiene**: 
    - **Sanitization**: All strings are stripped of Null Bytes (`\0`) to prevent binary-safe vulnerability exploits.
    - **Strict Typing**: Numeric fields are validated against strict decimal expectations.
- **Error Handling**: `mysqli_report(MYSQLI_REPORT_OFF)` is set to suppress default error echoing. Errors are captured and logged to the system log (`error_log`), showing only safe generic messages to users.
- **Network/Headers**: `src/security.php` injects critical headers:
    - `X-Frame-Options: DENY`: Blocks clickjacking.
    - `X-Content-Type-Options: nosniff`: Prevents MIME-sniffing.
    - `Content-Security-Policy`: Restricts content sources.
