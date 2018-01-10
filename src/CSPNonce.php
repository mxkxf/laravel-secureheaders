<?php

namespace MikeFrancis\LaravelSecureHeaders;

class CSPNonce
{
    /**
     * @var string
     */
    protected static $generatedNonce;

    protected function __construct() {}

    /**
     * Get the CSP Nonce
     * @return string
     */
    public static function get(): string
    {
        if (static::$generatedNonce === null) {
            static::$generatedNonce = base64_encode(str_random(32));
        }

        return static::$generatedNonce;
    }

}
