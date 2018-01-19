<?php

use Illuminate\Container\Container;
use MikeFrancis\LaravelSecureHeaders\Exceptions\ContentSecurityPolicyNotFoundException;

if (!function_exists('csp_nonce')) {
    /**
     * The nonce will be regenerated once per page load.
     *
     * @param string $friendlyDirective
     * @return string
     * @throws ContentSecurityPolicyNotFoundException
     */
    function csp_nonce(string $friendlyDirective)
    {
        $app = Container::getInstance();
        $request = $app['request'];
        $cspHeader = $request->headers->get('content-security-policy');

        if (!$cspHeader) {
            throw new ContentSecurityPolicyNotFoundException();
        }

        $parts = explode(' ', $cspHeader, 2);

        if ($parts[0] === $friendlyDirective) {
            return $parts[1];
        }

        return null;
    }
}
