<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

use Illuminate\Contracts\Config\Repository;
use MikeFrancis\LaravelSecureHeaders\ServiceProvider;
use PHPUnit\Framework\TestCase;

class ServiceProviderTest extends TestCase
{
    /**
     * Ensure that the service provider can be registered.
     *
     * @return void
     */
    public function testServiceProviderCanRegister()
    {
        $config = $this->createMock(Repository::class);
        $config->method('get')->willReturn([]);

        $app = [
            'config' => $config,
        ];

        $serviceProvider = new ServiceProvider($app);
        $serviceProvider->register();
    }

    /**
     * Ensure that the service provider can be booted.
     *
     * @return void
     */
    public function testServiceProviderCanBoot()
    {
        $config = $this->createMock(Repository::class);
        $config->method('get')->willReturn([]);

        $app = [
            'config' => $config,
        ];

        $serviceProvider = new ServiceProvider($app);
        $serviceProvider->boot();
    }
}
