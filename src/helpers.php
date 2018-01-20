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

        $contentTypes = explode('; ', $cspHeader);

        foreach ($contentTypes as $contentType) {
            preg_match("/([a-z]+)-src 'nonce-([^']+)'/", $contentType, $matches);

            if ($matches[1] === $friendlyDirective) {
                return $matches[2];
            }
        }

        return null;
    }
}
