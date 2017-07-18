# Laravel SecureHeaders

Secure Headers wrapper for Laravel.

Based on [aidantwoods/SecureHeaders](https://github.com/aidantwoods/SecureHeaders).

## Installation

Require the `mikefrancis/laravel-secureheaders` package in your `composer.json` and update your dependencies:

```bash
composer require mikefrancis/laravel-secureheaders
```
Add the service provider to your `config/app.php` providers array:

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
