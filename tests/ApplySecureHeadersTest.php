<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use MikeFrancis\LaravelSecureHeaders\ApplySecureHeaders;
use PHPUnit\Framework\TestCase;
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
        $result = $this->applySecureHeadersWithConfig(new Response, []);
        $this->assertBaseHeadersPresent($result->headers->all());
    }

    /**
     * Ensure that HSTS is applied.
     *
     * @return void
     */
    public function testHsts()
    {
        // configuration
        $configMap = [
            ['secure-headers.hsts.enabled', false, true],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
        // configuration
        $configMap = [
            ['secure-headers.hsts.enabled', false, true],
            ['secure-headers.hsts.maxAge', null, 1337],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
        $headers = $result->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
        $this->assertSame($headers['strict-transport-security'][0], 'max-age=1337');
        $this->assertBaseHeadersPresent($headers);
    }

    /**
     * Ensure that HSTS includeSubdomains is applied.
     *
     * @return void
     */
    public function testHstsSubdomains()
    {
        // configuration
        $configMap = [
            ['secure-headers.hsts.enabled', false, true],
            ['secure-headers.hsts.includeSubDomains', null, true],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
        // configuration
        $configMap = [
            ['secure-headers.hsts.enabled', false, true],
            ['secure-headers.hsts.preload', null, true],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
        // configuration
        $configMap = [
            ['secure-headers.hsts.enabled', false, true],
            ['secure-headers.hsts.includeSubDomains', null, true],
            ['secure-headers.hsts.preload', null, true],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
        $response = $this->applySecureHeadersWithConfig(new Response());
        $headers = $response->headers->all();
        // configuration
        $configMap = [
            ['secure-headers.hsts.enabled', false, true],
            ['secure-headers.safeMode', false, true],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
            'expectCT.maxAge' => $time,
        ];

        $response = $this->applySecureHeadersWithConfig(new Response, $config);
        $headers = $response->headers->all();

        $this->assertEquals("max-age={$time}", $headers['expect-ct'][0]);
    }

    /*
     * Ensure that safe-mode neuters strict-mode.
     *
     * @return void
     */
    public function testStrictModeAndSafeMode()
    {
        // configuration
        $configMap = [
            ['secure-headers.strictMode', false, true],
            ['secure-headers.safeMode', false, true],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
        // configuration
        $configMap = [
            ['secure-headers.strictMode', false, true],
        ];

        $response = new Response;
        $response->headers->set('set-cookie', 'session=secret');
        $response->headers->set('content-security-policy', "default-src 'nonce-1234'");

        $result  = $this->applySecureHeadersWithConfig($response, $configMap);
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
        // configuration
        $configMap = [
            ['secure-headers.csp', [], [
                'default' => 'self',
                'base' => 'self',
                'script' => ['https://example.com', 'self'],
                'object' => ['none'],
            ]],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
        // configuration
        $configMap = [
            ['secure-headers.cspro', [], [
                'default' => 'self',
                'base' => 'self',
                'script' => ['https://example.com', 'self'],
                'object' => ['none'],
            ]],
        ];

        $result  = $this->applySecureHeadersWithConfig(new Response, $configMap);
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
     * Apply SecureHeaders from the given config to a Response.
     *
     * @param Response $response
     * @param ?array $configMap
     * @return Response
     */
    private function applySecureHeadersWithConfig(
        Response $response,
        array $configMap = null
    ) {
        $config = $this->createMock(Repository::class);
        if (isset($configMap)) {
            $config->method('get')->will($this->returnValueMap($configMap));
        }
        // return default (second arg) if not in configuration
        $config->method('get')->will($this->returnArgument(1));

        $secureHeaders = new SecureHeaders;
        $secureHeaders->errorReporting(false);
        $middleware    = new ApplySecureHeaders($config, $secureHeaders);

        return $middleware->handle(
            new Request,
            function () use ($response) { return $response; }
        );
    }
}
