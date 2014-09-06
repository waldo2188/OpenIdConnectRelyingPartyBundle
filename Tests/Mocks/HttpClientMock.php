<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Tests\Mocks;

use Buzz\Client\AbstractCurl;   
use Buzz\Message\Request;
use Buzz\Message\Response;
use Buzz\Message\RequestInterface;
use Buzz\Message\MessageInterface;

/**
 * HttpClientMock
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class HttpClientMock extends AbstractCurl
{
    public $response = null;
    public $request;
    

    public function send(RequestInterface $request, MessageInterface $response)
    {
        $this->request = $request;
        
        $response->setHeaders($this->response->getHeaders());
        $response->setContent($this->response->getContent());
    }
    
    public function getRequest()
    {
        return $this->request;
    }
    
    public function setResponseContent($isOk, $headers, $content)
    {
        $this->response = new Response();
        $this->response->setContent($content);
        $this->response->setHeaders($headers);
    }
}
