FROM php:8.2-apache

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set recommended PHP settings for security
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

# Configure upload limits
RUN echo "upload_max_filesize = 6M" >> "$PHP_INI_DIR/php.ini" && \
    echo "post_max_size = 7M" >> "$PHP_INI_DIR/php.ini" && \
    echo "max_execution_time = 60" >> "$PHP_INI_DIR/php.ini" && \
    echo "memory_limit = 128M" >> "$PHP_INI_DIR/php.ini"

# Create quarantine directory (outside webroot)
RUN mkdir -p /var/quarantine/uploads && \
    mkdir -p /var/log/csv-security && \
    chown -R www-data:www-data /var/quarantine && \
    chown -R www-data:www-data /var/log/csv-security && \
    chmod 700 /var/quarantine && \
    chmod 700 /var/log/csv-security

# Set working directory
WORKDIR /var/www/html

# Expose port 80
EXPOSE 80
