FROM php:8.2-apache

# Install dependencies for GD, EXIF, and Libvips
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libwebp-dev \
    libgif-dev \
    libfreetype6-dev \
    libvips-tools \
    libvips-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j$(nproc) gd exif pdo pdo_mysql

# Enable Apache Mod Rewrite
RUN a2enmod rewrite

# Create necessary directories
RUN mkdir -p /var/www/quarantine /var/www/html/uploads /var/log/app \
    && chown -R www-data:www-data /var/www/quarantine /var/www/html/uploads /var/log/app \
    && chmod -R 755 /var/www/html/uploads \
    && chmod -R 700 /var/www/quarantine

# Set working directory
WORKDIR /var/www/html

# Copy source code
COPY src/ .

# Expose port 80
EXPOSE 80
