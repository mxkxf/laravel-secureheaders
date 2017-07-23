<?php

namespace MikeFrancis\LaravelSecureHeaders\Tests;

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
        $serviceProvider = $this->createPartialMock(ServiceProvider::class, ['mergeConfigFrom']);
        $serviceProvider->register();
    }

    /**
     * Ensure that the service provider can be booted.
     *
     * @return void
     */
    public function testServiceProviderCanBoot()
    {
        $serviceProvider = $this->createPartialMock(ServiceProvider::class, ['publishes']);
        $serviceProvider->boot();
    }
}
