FROM php:8.2-apache

# Install dependencies
RUN apt-get update && apt-get install -y \
    libmagic-dev \
    libicu-dev \
    qpdf \
    poppler-utils \
    img2pdf \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql intl

# Enable Apache modules
RUN a2enmod rewrite headers

# Configure PHP for security
RUN { \
    echo 'display_errors=Off'; \
    echo 'log_errors=On'; \
    echo 'error_log=/var/log/pdf-security/php_errors.log'; \
    echo 'upload_max_filesize=10M'; \
    echo 'post_max_size=12M'; \
    echo 'expose_php=Off'; \
    } > /usr/local/etc/php/conf.d/security.ini

# Create directories and set permissions
RUN mkdir -p /var/quarantine/uploads /var/log/pdf-security \
    && chown -R www-data:www-data /var/quarantine /var/log/pdf-security \
    && chmod -R 770 /var/quarantine /var/log/pdf-security

# Set working directory
WORKDIR /var/www/html

# Copy source code
COPY src/ .

# Security: Ensure quarantine is NOT accessible via web
RUN echo '<Directory /var/quarantine/>\n\
    Order Deny,Allow\n\
    Deny from all\n\
    </Directory>' >> /etc/apache2/apache2.conf

EXPOSE 80
