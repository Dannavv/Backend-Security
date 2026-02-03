FROM php:8.2-apache

# Install required extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN apt-get update && apt-get install -y libicu-dev && docker-php-ext-install intl

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Security hardening
RUN echo "expose_php = Off" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "display_errors = Off" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "log_errors = On" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "error_log = /var/log/php_errors.log" >> /usr/local/etc/php/conf.d/security.ini

# Set working directory
WORKDIR /var/www/html

# Copy application files
COPY include/ /var/www/html/include/
COPY public/ /var/www/html/public/
COPY test*.php /var/www/html/

# Create logs directory
RUN mkdir -p /var/www/html/logs && chmod 777 /var/www/html/logs

# Set Apache document root
ENV APACHE_DOCUMENT_ROOT /var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf

EXPOSE 80
