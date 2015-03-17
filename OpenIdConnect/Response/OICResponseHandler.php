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
        
        if($response->getStatusCode() >= Response::HTTP_UNAUTHORIZED) {
            if(($authError = $response->getHeader("WWW-Authenticate")) !== null){
                preg_match ('/^Basic realm="(.*)"$/', $authError, $matches);
                $content = array('error' => "Authentication fail", 'error_description' => $matches[1]);                
            }
        }elseif($response->getStatusCode() >= Response::HTTP_BAD_REQUEST) {
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
        if($this->isJson($content['id_token'])) {
            
            $jsonDecoded = $this->getJsonEncodedContent($content['id_token']);
            
            $content['id_token'] = new \JOSE_JWT($jsonDecoded); 
                        
        } else {
            $content['id_token'] = $this->getJwtEncodedContent($content['id_token']);
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

        if(!$content instanceof \JOSE_JWT) {
            return $content;
        }
  
        $this->verifySignedJwt($content);
      
        return $content->claims;
    }
    
    
    /**
     * getContent
     * 
     * @param \Buzz\Message\Response $response
     * @return type
     */
    protected function getContent(HttpClientResponse $response)
    {
        $contentType = explode(';', $response->getHeader("Content-Type"));
        if(in_array('application/json', $contentType)) {
            return $this->getJsonEncodedContent($response->getContent());
        } elseif(in_array('application/jwt', $contentType)) {
            return $this->getJwtEncodedContent($response->getContent());
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
        
        $this->verifySignedJwt($jwt);
        
        return $jwt;
    }
    
    /**
     * Check the signature of an JSON Web Token if there is a signature
     * @param JOSE_JWT $jwt
     * @return JOSE_JWT
     * @throws OICException\InvalidIdSignatureException
     */
    protected function verifySignedJwt(\JOSE_JWT $jwt)
    {
        if (array_key_exists('alg', $jwt->header)) {
                        
            $key = null;
            
            // get the right key base on the algorithm
            if(substr($jwt->header['alg'], 0, 2) == 'HS') {
                
                $key = $this->options['client_secret'];
                
            } elseif (substr($jwt->header['alg'], 0, 2) == 'RS') {
            
                // TODO add the ability to use another jku. Don't forget the "kid" attribute.
                // If the jku content more than one JWK, the KID must be used for select the right one
                //if(array_key_exists('jku', $jwt->header))
                
                $jwkSetJsonObject = $this->jwkHandler->getJwk();
                $jwkSet = new \JOSE_JWKSet();
                $jwkSet->setJwksFromJsonObject($jwkSetJsonObject);
                $key = $jwkSet->filterJwk("use", \JOSE_JWK::JWK_USE_SIG);
                
                if ($key === null && array_key_exists(0, $jwkSet->keys) ) {
                   $key = $jwkSet->keys[0];
                }
                
            }

            if ($key !== null) {

                $jws = new \JOSE_JWS($jwt);
                
                try {
    
                    $jws->verify($key);
                     
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
            
            if(!array_key_exists('error_description', $content)) {
                $content['error_description'] = $content['error'];
            }
            
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
                case 'unauthorized_client':
                    throw new OICException\InvalidClientOrSecretException($content['error_description']);
                    break;
                default :
                    throw new OICException\InvalidRequestException($content['error_description']);
                    break;
            }
        }
        
        return false;
    }

    private function isJson($string)
    {
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }

}
