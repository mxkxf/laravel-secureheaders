<?php

namespace MikeFrancis\LaravelSecureHeaders;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Http\HttpAdapter;
use Symfony\Component\HttpFoundation\Response;

class Adapter implements HttpAdapter
{
    /**
     * Instance of Laravel Response.
     *
     * @var Response
     */
    private $response;

    /**
     * Constructor.
     *
     * @param Response $response
     */
    public function __construct(Response $response)
    {
        $this->response = $response;
    }

    /**
     * Send the given headers, overwriting all previously sent headers.
     *
     * The HttpAdapter MUST delete headers before writing. Headers MUST be
     * added (and not replaced), such that if multiple headers with the same
     * name are contained within the HeaderBag, all MUST be sent.
     * (e.g. setting multiple cookies with multiple headers named 'Set-Cookie').
     *
     * The HttpAdapter MUST NOT attempt to place 'Set-Cookie' headers into a
     * cookie-jar (placing cookies into a cookie-jar will likely cause loss of
     * properties that are not yet implemeted by the cookie-jar, e.g. (at time
     * of writing) the `SameSite` cookie attribute).
     *
     * @api
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function sendHeaders(HeaderBag $headers)
    {
        $headersToRemove = $this->response->headers->all();

        foreach ($headersToRemove as $name => $headerLines) {
            $this->response->headers->remove($name);
        }

        foreach ($headers->get() as $header) {
            $this->response->headers->set($header->getName(), $header->getValue(), false);
        }
    }

    /**
     * Retrieve the current list of already-sent (or planned-to-be-sent) headers
     *
     * @return HeaderBag
     */
    public function getHeaders()
    {
        $headerLines = [];

        foreach ($this->response->headers->all() as $name => $lines) {
            foreach ($lines as $line) {
                $headerLines[] = "$name: $line";
            }
        }

        return HeaderBag::fromHeaderLines($headerLines);
    }
}
