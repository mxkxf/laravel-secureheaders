<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use MikeFrancis\LaravelSecureHeaders\ApplySecureHeaders;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Symfony\Component\HttpFoundation\Response;

abstract class TestCase extends PHPUnitTestCase
{
  /**
   * Assert base headers are present given an array of headers.
   *
   * @param array<string, string[]> $headers
   * @return void
   */
    protected function assertBaseHeadersPresent(array $headers)
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
   * @param array $configMap
   * @return Response
   */
    protected function applySecureHeadersWithConfig(Response $response, array $configMap = [])
    {
      // convert the configMap dot keys into deeply nested array
        $configMap = [
        'secure-headers' => !empty($configMap)
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
            return Arr::get($configMap, $key, $default);
        }));

        $secureHeaders = new SecureHeaders();
        $secureHeaders->errorReporting(false);
        $middleware = new ApplySecureHeaders($config, $secureHeaders);

        return $middleware->handle(new Request, function () use ($response) {
            return $response;
        });
    }

  /**
   * Set an array key/value without mutating the original.
   *
   * @param array $array
   * @param string $key
   * @param mixed $value
   * @return array
   */
    protected static function nonMutatingDataFill(array $array, string $key, $value)
    {
        data_fill($array, $key, $value);
        return $array;
    }
}
