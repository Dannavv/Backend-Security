FROM php:8.2-apache

# Install system dependencies for all security modules
RUN apt-get update && apt-get install -y \
    libvips-tools \
    qpdf \
    poppler-utils \
    img2pdf \
    libpng-dev \
    libjpeg62-turbo-dev \
    libfreetype6-dev \
    libwebp-dev \
    libzip-dev \
    libicu-dev \
    zip \
    unzip \
    mariadb-client \
    && rm -rf /var/lib/apt/lists/*

# Configure and Install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install \
    gd \
    mysqli \
    pdo_mysql \
    zip \
    intl

# Enable Apache modules
RUN a2enmod rewrite headers

# Set working directory
WORKDIR /var/www/html

# Create necessary directories and set permissions
RUN mkdir -p /var/www/uploads /var/www/quarantine /var/www/logs \
    && chown -R www-data:www-data /var/www/html /var/www/uploads /var/www/quarantine /var/www/logs \
    && chmod -R 775 /var/www/html /var/www/uploads /var/www/quarantine /var/www/logs

# Copy configuration files if needed
# COPY ./src/php.ini /usr/local/etc/php/conf.d/custom.ini

EXPOSE 80
