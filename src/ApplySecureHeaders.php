<?php

namespace MikeFrancis\LaravelSecureHeaders;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;

class ApplySecureHeaders
{
    /**
     * Instance of Config Repository.
     *
     * @var Repository
     */
    private $config;

    /**
     * Instance of SecureHeaders Utility.
     *
     * @var SecureHeaders
     */
    private $headers;

    /**
     * ApplySecureHeaders constructor.
     *
     * @param Repository $config
     * @param SecureHeaders $headers
     */
    public function __construct(Repository $config, SecureHeaders $headers)
    {
        $this->config = $config;
        $this->headers = $headers;
    }

    /**
     * Applies SecureHeaders to the request response.
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $this->setHsts();
        $this->setCsp();
        $this->setMode();
        $this->setExpectCT();

        $adapter = new Adapter($response);

        $this->headers->apply($adapter);

        return $response;
    }

    /**
     * Set any Content Security Policy headers.
     *
     * @return void
     */
    private function setCsp()
    {
        $csp = $this->config->get('secure-headers.csp', []);

        $this->headers->csp($csp);
    }

    /**
     * Set any Strict-Transport-Policy headers.
     *
     * @return void
     */
    private function setHsts()
    {
        if ($this->config->get('secure-headers.hsts.enabled', false)) {
            $this->headers->hsts();
        }
    }

    /**
     * Set safe mode, if it is required.
     *
     * @return void
     */
    private function setMode()
    {
        if ($this->config->get('secure-headers.safeMode', false)) {
            $this->headers->safeMode();
        }
    }

    /**
     * Set any Expect-CT headers.
     *
     * @return void
     */
    private function setExpectCT()
    {
        if ($expectCT = $this->config->get('secure-headers.expectCT', false)) {
            $this->headers->expectCT(
                array_get($expectCT, 'maxAge'),
                array_get($expectCT, 'enforce'),
                array_get($expectCT, 'reportUri')
            );
        }
    }
}
