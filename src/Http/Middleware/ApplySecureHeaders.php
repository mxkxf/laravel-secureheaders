<?php

namespace MikeFrancis\LaravelSecureHeaders\Http\Middleware;

use Aidantwoods\SecureHeaders\SecureHeaders;
use Closure;
use Illuminate\Http\Request;

class ApplySecureHeaders
{
    /**
     * Applies SecureHeaders to the request response.
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $headers = new SecureHeaders();
        $headers->apply();

        return $next($request);
    }
}
