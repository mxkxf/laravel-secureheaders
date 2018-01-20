<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use MikeFrancis\LaravelSecureHeaders\ApplySecureHeaders;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Symfony\Component\HttpFoundation\Response;

abstract class TestCase extends PHPUnitTestCase
{
    /**
     * Set the request on the container.
     *
     * @param Response $response
     * @return void
     */
    protected function setRequest(Response $response)
    {
        $container = new Container();
        $container['request'] = $response;

        Container::setInstance($container);
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
}
