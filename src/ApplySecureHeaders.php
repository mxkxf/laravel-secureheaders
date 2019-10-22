<?php

namespace MikeFrancis\LaravelSecureHeaders;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;

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

        $this->headers->errorReporting($this->config->get('secure-headers.errorReporting', true));

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

        $cspro = $this->config->get('secure-headers.cspro', []);
        $this->headers->cspro($cspro);
    }

    /**
     * Set any Strict-Transport-Policy headers.
     *
     * @return void
     */
    private function setHsts()
    {
        if ($hsts = $this->config->get('secure-headers.hsts', false)) {
            if (isset($hsts['maxAge'])) {
                $this->headers->hsts($hsts['maxAge']);
            } elseif (isset($hsts['enabled'])) {
                $this->headers->hsts();
            } else {
                return;
            }

            if (isset($hsts['includeSubDomains'])) {
                $this->headers->hstsSubdomains($hsts['includeSubDomains']);
            }

            if (isset($hsts['preload'])) {
                $this->headers->hstsPreload($hsts['preload']);
            }
        }
    }

    /**
     * Set safe or (inclusive) strict mode, if it is required.
     *
     * @return void
     */
    private function setMode()
    {
        if ($this->config->get('secure-headers.safeMode', false)) {
            $this->headers->safeMode();
        }

        if ($this->config->get('secure-headers.strictMode', false)) {
            $this->headers->strictMode();
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
                Arr::get($expectCT, 'maxAge'),
                Arr::get($expectCT, 'enforce'),
                Arr::get($expectCT, 'reportUri')
            );
        }
    }
}
