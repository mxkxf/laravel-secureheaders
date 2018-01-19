<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use MikeFrancis\LaravelSecureHeaders\ApplySecureHeaders;
use MikeFrancis\LaravelSecureHeaders\Exceptions\ContentSecurityPolicyNotFoundException;
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

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
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

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
        $headers = $response->headers->all();

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

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
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
            'expectCT' => [
                'maxAge' => $time,
            ],
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
        $headers = $response->headers->all();

        $this->assertEquals("max-age={$time}", $headers['expect-ct'][0]);
    }

    /**
     * Ensure CSP nonces can be added.
     *
     * @return void
     */
    public function testCspNonce()
    {
        $config = [
            'cspNonces' => ['script-src'],
        ];

        $response = $this->applySecureHeadersWithConfig(new Response(), $config);
        $headers = $response->headers->all();

        $this->setRequest($response);

        $this->assertContains($config['cspNonces'][0], $headers['content-security-policy'][0]);
        $this->assertContains('nonce-', csp_nonce($config['cspNonces'][0]));
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

    /**
     * Apply SecureHeaders from the given config to a Response.
     *
     * @param Response $response
     * @param array $configMap
     * @return Response
     */
    private function applySecureHeadersWithConfig(Response $response, array $configMap = [])
    {
        // convert the configMap dot keys into deeply nested array
        $configMap = [
            'secure-headers' => ! empty($configMap)
                ? array_merge_recursive(...array_map(
                    [self::class, 'nonMutatingDataFill'],
                    array_fill(0, count($configMap), []),
                    array_keys($configMap),
                    $configMap
                ))
                : []
        ];
        
        /** @var Repository|\PHPUnit_Framework_MockObject_MockObject $config */
        $config = $this->createMock(Repository::class);
        $config->expects($this->any())
            ->method('get')
            ->with($this->anything())
            ->will($this->returnCallback(function (string $key, $default) use ($configMap) {
                return array_get($configMap, $key, $default);
            }));

        $secureHeaders = new SecureHeaders();
        $secureHeaders->errorReporting(false);

        $middleware = new ApplySecureHeaders($config, $secureHeaders);

        return $middleware->handle(new Request, function () use ($response) { return $response; });
    }

    /**
     * Fill an array without mutating the data.
     *
     * @param array $array
     * @param string $key
     * @param $value
     * @return array
     */
    private static function nonMutatingDataFill(array $array, string $key, $value) {
        data_fill($array, $key, $value);
        return $array;
    }

    /**
     * Set the request on the container.
     *
     * @param Response $response
     * @return void
     */
    private function setRequest(Response $response)
    {
        $container = new Container();
        $container['request'] = $response;

        Container::setInstance($container);
    }
}
