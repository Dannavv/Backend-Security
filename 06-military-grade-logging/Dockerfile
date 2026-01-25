FROM php:8.2-apache

# 1. Install system dependencies
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    zip \
    unzip \
    git \
    mariadb-client \
    && rm -rf /var/lib/apt/lists/*

# 2. Install PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql gd

# 3. Enable Apache Modules
RUN a2enmod rewrite log_forensic headers ssl

# 4. Configure Apache for Military-Grade Logging
# We copy our custom config to the available configs and enable it
COPY config/apache-logging.conf /etc/apache2/conf-available/erp-logging.conf

# We also need to Ensure the Log directory exists and has correct permissions
RUN mkdir -p /var/www/html/logs && \
    chown -R www-data:www-data /var/www/html/logs && \
    chmod -R 775 /var/www/html/logs

# Enable our custom logging configuration
RUN a2enconf erp-logging

# Change DocumentRoot to /var/www/html/public
RUN sed -i 's|/var/www/html|/var/www/html/public|g' /etc/apache2/sites-available/000-default.conf && \
    sed -i 's|CustomLog .*|CustomLog ${APACHE_LOG_DIR}/erp_access.log erp_forensic|g' /etc/apache2/sites-available/000-default.conf

# 5. Set working directory
WORKDIR /var/www/html

# 6. Set environment variables
ENV APP_ENV=production

# 7. Expose port 80
EXPOSE 80

# Keep default entrypoint (apache2-foreground)
