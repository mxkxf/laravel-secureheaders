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
     * Ensure that safe-mode neuters hsts.
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
            'maxAge' => $time,
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), 'expectCT', $config);
        $headers = $response->headers->all();

        $this->assertEquals("max-age={$time}", $headers['expect-ct'][0]);
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
        ?array $configMap = null
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
