<?php

use MikeFrancis\LaravelSecureHeaders\CSPNonce;

if (!function_exists('csp_nonce')) {
    /**
     * Provide a base-64 CSP nonce that can be used for inline styles.
     * The nonce will be regenerated once per pageload.
     * @return string
     */
    function csp_nonce(): string
    {
        return CSPNonce::get();
    }
}
