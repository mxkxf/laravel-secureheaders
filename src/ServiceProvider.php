<?php

namespace MikeFrancis\LaravelSecureHeaders;

use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;

class ServiceProvider extends IlluminateServiceProvider
{
    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom($this->getConfigPath(), 'secure-headers');
    }

    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            $this->getConfigPath() => config_path('secure-headers.php'),
        ]);
    }

    /**
     * Get the path to the config.
     *
     * @return string
     */
    private function getConfigPath(): string
    {
        return __DIR__ . '/../config/secure-headers.php';
    }
}
