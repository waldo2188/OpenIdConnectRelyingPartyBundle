<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Response;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception as OICException;
use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\JWK\JWKSetHandler;
use Buzz\Message\Response as HttpClientResponse;
use Symfony\Component\Serializer\Encoder\JsonDecode;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\HttpFoundation\Response;


/**
 * OICResponseHandler
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICResponseHandler
{
    /**
     * @var array
     */
    protected $options;
    
    /**
     * @var JWKSetHandler
     */
    protected $jwkHandler;
    
    /**
     * __construct
     * 
     * @param \Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\JWK\JWKSetHandler $jwkHandler
     * @param type $options
     */
    public function __construct(JWKSetHandler $jwkHandler, $options)
    {
        $this->jwkHandler = $jwkHandler;
        $this->options = $options;
    }

     /**
     * Search error in header and in content of the response.
     * If an error is found an exception is throw.
     * If all is clear, the content is Json decoded (if needed) and return as an array
     * 
     * @param \Buzz\Message\Response $response
     * @return array $content
     */
    public function handleHttpClientResponse(HttpClientResponse $response)
    {  
        $content = $this->getContent($response);
                
        if($response->getStatusCode() >= Response::HTTP_BAD_REQUEST) {
            if(($bearerError = $response->getHeader("WWW-Authenticate")) !== null){
                preg_match ('/^Bearer error="(.*)", error_description="(.*)"$/', $bearerError, $matches);
                $content = array('error' => $matches[1], 'error_description' => $matches[1]);                
            }
        }

        if(!$this->hasError($content)) {
            return $content;
        }
        
        return null;
    }
    
    /**
     * handleTokenAndAccessTokenResponse
     * 
     * @param \Buzz\Message\Response $response
     * @return \JOSE_JWT
     */
    public function handleTokenAndAccessTokenResponse(HttpClientResponse $response)
    {  
        $content = $this->handleHttpClientResponse($response);
        
        if($content == "") {
            return $content;
        }

        if($this->options['id_token_signed_response_alg'] !== null) {
            $content['id_token'] = $this->getJwtEncodedContent($content['id_token']);
        } else {
            $jsonDecode = new JsonDecode(true);
            $claims = $jsonDecode->decode($content['id_token'], JsonEncoder::FORMAT);
            $content['id_token'] = new \JOSE_JWT($claims);
        }

        return $content;
    }
    
    /**
     * handleEndUserinfoResponse
     * 
     * @param \Buzz\Message\Response $response
     * @return \JOSE_JWT
     * @throws OICException\InvalidIdSignatureException
     */
    public function handleEndUserinfoResponse(HttpClientResponse $response)
    {  
        $content = $this->handleHttpClientResponse($response);

        // Check if Userinfo Signed Response Alg
        if($this->options['userinfo_signed_response_alg'] !== null) {
            if($content instanceof \JOSE_JWT) {

                return $content->claims;
                
            } else {
                throw new OICException\InvalidIdSignatureException("Enduser signature is missing");
            }
        }
        
        return $content;        
    }
    
    
    /**
     * getContent
     * 
     * @param \Buzz\Message\Response $response
     * @return type
     */
    protected function getContent(HttpClientResponse $response)
    {
        switch ($response->getHeader("Content-Type")) {
            case 'application/json': return $this->getJsonEncodedContent($response->getContent());
                break;
            case 'application/jwt': return $this->getJwtEncodedContent($response->getContent());
                break;
        }
    }
    
    /**
     * @param string $content
     * @return array
     */
    protected function getJsonEncodedContent($content)
    {
        $jsonDecode = new JsonDecode(true);
        return $jsonDecode->decode($content, JsonEncoder::FORMAT);
    }
    
    /**
     * @param string $content
     * @return array
     */
    protected function getJwtEncodedContent($content)
    {
        $jwt = \JOSE_JWT::decode($content);

        if (array_key_exists('jku', $jwt->header)) {
            $jwkSetJsonObject = $this->jwkHandler->getJwk();

            if ($jwkSetJsonObject !== null) {
                $jwkSet = new \JOSE_JWKSet();
                $jwkSet->setJwksFromJsonObject($jwkSetJsonObject);

                $jws = new \JOSE_JWS($jwt);
                
                try {
                    
                    $jws->verify($jwkSet);
                    
                } catch (\Exception $e) {
                    throw new OICException\InvalidIdSignatureException($e->getMessage());                    
                }
            }
        }
        
        return $jwt;
    }

    /**
     * @param array|object $content
     * @return boolean
     * @throws OICException\InvalidRequestException
     * @throws OICException\InvalidResponseTypeException
     * @throws OICException\InvalidAuthorizationCodeException
     * @throws OICException\InvalidClientOrSecretException
     * @throws OICException\UnsuportedGrantTypeException
     */
    public function hasError($content)
    {   
        if(!is_array($content)) {
            return false;
        }

        if(array_key_exists('error', $content)) {
            switch ($content['error']) {
                case 'invalid request':
                case 'invalid_request':
                    throw new OICException\InvalidRequestException($content['error_description']);
                    break;
                case 'invalid_response_type':
                    throw new OICException\InvalidResponseTypeException($content['error_description']);
                    break;
                case 'invalid_authorization_code':
                    throw new OICException\InvalidAuthorizationCodeException($content['error_description']);
                    break;
                case 'invalid_client':
                    throw new OICException\InvalidClientOrSecretException($content['error_description']);
                    break;
                case 'unsupported_grant_type':
                    throw new OICException\UnsuportedGrantTypeException($content['error_description']);
                    break;
            }
        }
        
        return false;
    }

}
