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
     * Ensure that the middleware adds the appropriate headers.
     *
     * @return void
     */
    public function testMiddlewareAddsAppropriateHeaders()
    {
        $config = $this->createMock(Repository::class);
        $config->method('get')->willReturn(['csp' => []]);
        $config->method('get')->willReturn(true); // hsts
        $config->method('get')->willReturn(true); // safeMode

        $request = new Request();

        $response = new Response();
        $response->headers->set('set-cookie', 'someCookieToIgnore');

        $secureHeaders = new SecureHeaders();

        $middleware = new ApplySecureHeaders($config, $secureHeaders);

        $result = $middleware->handle($request, function ($foo) use ($response) {
            return $response;
        });

        $headers = $result->headers->all();

        $this->assertArrayHasKey('x-xss-protection', $headers);
        $this->assertArrayHasKey('x-frame-options', $headers);
    }
}
