<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

use MikeFrancis\LaravelSecureHeaders\Exceptions\ContentSecurityPolicyNotFoundException;
use Symfony\Component\HttpFoundation\Response;

class ApplySecureHeadersTest extends TestCase
{
    /**
     * Ensure that the middleware adds the base headers.
     *
     * @return void
     */
    public function testMiddlewareAddsBaseHeaders()
    {
        $result = $this->applySecureHeadersWithConfig(new Response(), []);

        $this->assertBaseHeadersPresent($result->headers->all());
    }

    /**
     * Ensure that HSTS is applied.
     *
     * @return void
     */
    public function testHsts()
    {
        $configMap = [
            'hsts' => [
                'enabled' => true,
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=31536000');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that HSTS max-age is applied.
     *
     * @return void
     */
    public function testHstsMaxAge()
    {
        $configMap = [
            'hsts' => [
                'maxAge' => 1337,
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=1337');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that HSTS is not applied if insufficient criteria met.
     *
     * @return void
     */
    public function testHstsInvalid()
    {
        $configMap = [
            'hsts' => [
                'includeSubDomains' => true,
                'preload' => true,
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayNotHasKey('strict-transport-security', $headers);
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that HSTS includeSubdomains is applied.
     *
     * @return void
     */
    public function testHstsSubdomains()
    {
        $configMap = [
            'hsts' => [
                'enabled' => true,
                'includeSubDomains' => true,
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=31536000; includeSubDomains');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that HSTS preload is applied.
     *
     * @return void
     */
    public function testHstsPreload()
    {
        $configMap = [
            'hsts' => [
                'enabled' => true,
                'preload' => true,
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=31536000; preload');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that HSTS subdomains and preload is applied.
     *
     * @return void
     */
    public function testHstsSubdomainsAndPreload()
    {
        $configMap = [
            'hsts' => [
                'enabled' => true,
                'includeSubDomains' => true,
                'preload' => true,
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=31536000; includeSubDomains; preload');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that safe-mode neuters HSTS.
     *
     * @return void
     */
    public function testHstsAndSafeMode()
    {
        $configMap = [
            'hsts' => [
                'enabled' => true,
            ],
            'safeMode' => true,
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=86400');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that the middleware adds the expect-ct headers.
     *
     * @return void
     */
    public function testMiddlewareAddsExpectCTHeaders()
    {
        $time = time();
        $config = [
            'expectCT' => [
                'maxAge' => $time,
            ],
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
        $headers = $response->headers->all();

        $this->assertArrayHasKey('expect-ct', $headers);
        $this->assertEquals("max-age={$time}", $headers['expect-ct'][0]);
        $this->assertBaseHeadersPresent($headers);
    }

    /*
     * Ensure that safe-mode neuters strict-mode.
     *
     * @return void
     */
    public function testStrictModeAndSafeMode()
    {
        $configMap = [
            'strictMode' => true,
            'safeMode' => true,
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=86400');
        $this->assertArrayHasKey('expect-ct', $headers);
        $this->assertSame($headers['expect-ct'][0], 'max-age=31536000');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that strict-mode applies strictness.
     *
     * @return void
     */
    public function testStrictMode()
    {
        $configMap = [
            'strictMode' => true,
        ];

        $response = new Response;
        $response->headers->set('set-cookie', 'session=secret');
        $response->headers->set('content-security-policy', "default-src 'nonce-1234'");

        $result = $this->applySecureHeadersWithConfig($response, $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=31536000; includeSubDomains; preload');
        $this->assertArrayHasKey('expect-ct', $headers);
        $this->assertSame($headers['expect-ct'][0], 'max-age=31536000; enforce');
        $this->assertArrayHasKey('set-cookie', $headers);
        $this->assertSame($headers['set-cookie'][0], 'session=secret; path=/; secure; httponly; samesite=strict');
        $this->assertArrayHasKey('content-security-policy', $headers);
        $this->assertSame($headers['content-security-policy'][0], "default-src 'nonce-1234' 'strict-dynamic'");
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that CSP is applied.
     *
     * @return void
     */
    public function testCSP()
    {
        $configMap = [
            'csp' => [
                'default' => 'self',
                'base' => 'self',
                'script' => ['https://example.com', 'self'],
                'object' => ['none'],
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('content-security-policy', $headers);
        $this->assertSame(
            $headers['content-security-policy'][0],
            "default-src 'self'; base-uri 'self'; script-src https://example.com 'self'; object-src 'none'"
        );
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that CSP report-only is applied.
     *
     * @return void
     */
    public function testCSPRO()
    {
        $configMap = [
            'cspro' => [
                'default' => 'self',
                'base' => 'self',
                'script' => ['https://example.com', 'self'],
                'object' => ['none'],
            ],
        ];

        $result = $this->applySecureHeadersWithConfig(new Response(), $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('content-security-policy-report-only', $headers);
        $this->assertSame(
            $headers['content-security-policy-report-only'][0],
            "default-src 'self'; base-uri 'self'; script-src https://example.com 'self'; object-src 'none'"
        );
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Assert base headers are present given an array of headers.
     *
     * @param array<string, string[]> $headers
     * @return void
     */
    private function assertBaseHeadersPresent(array $headers)
    {
        $this->assertArrayHasKey('x-permitted-cross-domain-policies', $headers);
        $this->assertArrayHasKey('x-content-type-options', $headers);
        $this->assertArrayHasKey('expect-ct', $headers);
        $this->assertArrayHasKey('referrer-policy', $headers);
        $this->assertArrayHasKey('x-xss-protection', $headers);
        $this->assertArrayHasKey('x-frame-options', $headers);
    }

    /**
     * Ensure CSP nonces can be added.
     *
     * @return void
     */
    public function testCspNonce()
    {
        $config = [
            'cspNonces' => ['default', 'script'],
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
        $headers = $response->headers->all();

        $this->setRequest($response);

        $this->assertContains($config['cspNonces'][0], $headers['content-security-policy'][0]);
        $this->assertNotNull(csp_nonce($config['cspNonces'][0]));
    }

    /**
     * Ensure an exception is thrown if the csp_nonce function is used without setting the header.
     *
     * @return void
     * @throws ContentSecurityPolicyNotFoundException
     */
    public function testCspNonceFunctionFailsWhenNotSet()
    {
        $this->expectException(ContentSecurityPolicyNotFoundException::class);

        $this->setRequest(new Response());

        csp_nonce('foo');
    }
}
