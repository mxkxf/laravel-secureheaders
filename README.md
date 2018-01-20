# Laravel SecureHeaders

[![Packagist](https://img.shields.io/packagist/v/mikefrancis/laravel-secureheaders.svg)](https://packagist.org/packages/mikefrancis/laravel-secureheaders) [![Build Status](https://travis-ci.org/mikefrancis/laravel-secureheaders.svg?branch=master)](https://travis-ci.org/mikefrancis/laravel-secureheaders) [![codecov](https://codecov.io/gh/mikefrancis/laravel-secureheaders/branch/master/graph/badge.svg)](https://codecov.io/gh/mikefrancis/laravel-secureheaders)

SecureHeaders wrapper for Laravel.

Based on [aidantwoods/SecureHeaders](https://github.com/aidantwoods/SecureHeaders).

## Installation

Require the `mikefrancis/laravel-secureheaders` package in your `composer.json` and update your dependencies:

```bash
composer require mikefrancis/laravel-secureheaders
```

If you are using Laravel 5.5+, package discovery is enabled. For Laravel 5.4, add the service provider to your `config/app.php` providers array:

```php
MikeFrancis\LaravelSecureHeaders\ServiceProvider::class,
```

## Usage

To add more secure headers to your entire application, add the `ApplySecureHeaders` middleware in the `$middleware` 
property of `app/Http/Kernel.php` class:

```php
protected $middleware = [
    // ...
    \MikeFrancis\LaravelSecureHeaders\ApplySecureHeaders::class,
];
```

## Configuration

Some sensible defaults have been set in `config/secure-headers.php` but if you'd like to change these, copy the file to your own application's config using the following command:

```bash
php artisan vendor:publish --provider="MikeFrancis\LaravelSecureHeaders\ServiceProvider"
```

A typical configuration might look like this:

```php
<?php

return [
    // Safe Mode
    'safeMode' => false,

    // HSTS Strict-Transport-Security
    'hsts' => [
        'enabled' => true,
    ],

    // Content Security Policy
    'csp' => [
        'default' => [
            'self',
        ],
        'img-src' => [
            '*', // Allow images from anywhere
        ],
        'style-src' => [
            'self',
            'unsafe-inline', // Allow inline styles
            'https://fonts.googleapis.com', // Allow stylesheets from Google Fonts
        ],
        'font-src' => [
            'self',
            'https://fonts.gstatic.com', // Allow fonts from the Google Fonts CDN
        ],
    ],
];
```

For a full reference of Content Security Policy directives and their values, see [content-security-policy.com](https://content-security-policy.com).
