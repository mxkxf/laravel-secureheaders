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
     * Ensure that the middleware adds the default headers.
     *
     * @return void
     */
    public function testMiddlewareAddsDefaultHeaders()
    {
        $response = $this->applySecureHeadersWithConfig(new Response());
        $headers = $response->headers->all();
        // configuration
        $map = [
            ['secure-headers.csp', [], ['csp' => []]],
            ['secure-headers.hsts.enabled', false, true],
            ['secure-headers.safeMode', false, true],
        ];

        $config = $this->createMock(Repository::class);
        $config->method('get')->will($this->returnValueMap($map));
        // return default (second arg) if not in configuration
        $config->method('get')->will($this->returnArgument(1));

        $this->assertArrayHasKey('x-xss-protection', $headers);
        $this->assertArrayHasKey('x-frame-options', $headers);
    }

    /**
     * Ensure that the middleware enables safe mode.
     *
     * @return void
     */
    public function testMiddlewareAddsHSTSHeaders()
    {
        $config = [
            'hsts' => [
                'enabled' => true,
            ],
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), 'hsts.enabled', $config);
        $headers = $response->headers->all();

        $this->assertArrayHasKey('strict-transport-security', $headers);
    }

    /**
     * Ensure that the middleware enables safe mode.
     *
     * @return void
     */
    public function testMiddlewareEnablesSafeMode()
    {
        $config = [
            'hsts' => [
                'enabled' => true,
            ],
            'safeMode' => true,
        ];

        $response1 = $this->applySecureHeadersWithConfig(new Response(), 'hsts.enabled', $config);
        $response2 = $this->applySecureHeadersWithConfig($response1, 'safeMode', $config);
        $headers = $response2->headers->all();

        $this->assertNotEquals('max-age=31536000', $headers['strict-transport-security'][0]);
    }

    /**
     * Ensure that the middleware adds the CSP headers.
     *
     * @return void
     */
    public function testMiddlewareAddsCSPHeaders()
    {
        $config = [
            'csp' => [
                'default' => 'self',
            ],
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), 'csp', $config);
        $headers = $response->headers->all();

        $this->assertArrayHasKey('content-security-policy', $headers);
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
     * Apply SecureHeaders from the given config to a Response.
     *
     * @param Response $response
     * @param string|null $key
     * @param array|null $configMap
     * @return Response
     */
    private function applySecureHeadersWithConfig(Response $response, string $key = null, array $configMap = null)
    {
        /** @var Repository|\PHPUnit_Framework_MockObject_MockObject $config */
        $config = $this->createMock(Repository::class);

        $config->expects($this->any())
            ->method('get')
            ->with($this->anything())
            ->will($this->returnCallback(function () use ($key, $configMap) {
                $args = func_get_args();

                if ($args[0] === "secure-headers.{$key}") {
                    return $configMap;
                }

                return $args[1];
            }));

        $secureHeaders = new SecureHeaders();
        $secureHeaders->errorReporting(false);
        $middleware = new ApplySecureHeaders($config, $secureHeaders);

        return $middleware->handle(new Request, function () use ($response) { return $response; });
    }
}
