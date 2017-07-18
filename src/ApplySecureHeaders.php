<?php

namespace MikeFrancis\LaravelSecureHeaders;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

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

        $this->generateHsts();
        $this->generateCsp();

        $response = $this->setHeaders($response);

        return $response;
    }

    /**
     * Generate any Content Security Policy headers.
     *
     * @return void
     */
    private function generateCsp(): void
    {
        $csps = $this->config->get('secure-headers.hsts.csp', []);

        foreach ($csps as $key => $value) {
            $this->headers->csp($key, $value);
        }
    }

    /**
     * Generate any Strict-Transport-Policy headers.
     *
     * @return void
     */
    private function generateHsts(): void
    {
        if ($this->config->get('secure-headers.hsts.enabled')) {
            $this->headers->hsts();

            if ($this->config->get('secure-headers.hsts.safeMode')) {
                $this->headers->safeMode();
            }
        }
    }

    /**
     * Set the headers on the response.
     *
     * @param Response $response
     * @return Response
     */
    private function setHeaders(Response $response): Response
    {
        foreach ($this->headers as $header) {
            /** @var \Aidantwoods\SecureHeaders\Headers\RegularHeader $header */
            $response->headers->set($header->getName(), $header->getValue());
        }

        return $response;
    }
}
