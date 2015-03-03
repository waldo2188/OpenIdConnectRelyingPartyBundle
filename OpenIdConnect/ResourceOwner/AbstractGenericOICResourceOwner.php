<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwner;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwnerInterface;
use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken;
use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidIdTokenException;
use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidRequestException;
use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Constraint\ValidatorInterface;
use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Response\OICResponseHandler;
use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\NonceHelper;
use Buzz\Client\AbstractCurl;
use Buzz\Message\Request as HttpClientRequest;
use Buzz\Message\Response as HttpClientResponse;
use Buzz\Message\RequestInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Psr\Log\LoggerInterface;
/**
 * GenericOICResourceOwner
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
abstract class AbstractGenericOICResourceOwner implements ResourceOwnerInterface
{

    /**
     * @var HttpUtils 
     */
    private $httpUtils;

    /**
     * @var AbstractCurl
     */
    private $httpClient;

    /**
     * @var ValidatorInterface
     */
    private $idTokenValidator;

    /**
     * @var OICResponseHandler
     */
    private $responseHandler;

    /**
     * @var NonceHelper
     */
    private $nonceHelper;
    
    /**
     * @var array
     */
    private $options = array();
    
    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(
            HttpUtils $httpUtils, AbstractCurl $httpClient, 
            ValidatorInterface $idTokenValidator, 
            OICResponseHandler $responseHandler, 
            NonceHelper $nonceHelper, $options, LoggerInterface $logger = null)
    {
        $this->httpUtils = $httpUtils;
        $this->httpClient = $httpClient;
        $this->idTokenValidator = $idTokenValidator;
        $this->responseHandler = $responseHandler;
        $this->nonceHelper = $nonceHelper;
        $this->logger = $logger;


        if (array_key_exists("endpoints_url", $options)) {
            $options["authorization_endpoint_url"] = $options["endpoints_url"]["authorization"];
            $options["token_endpoint_url"] = $options["endpoints_url"]["token"];
            $options["userinfo_endpoint_url"] = $options["endpoints_url"]["userinfo"];
            unset($options["endpoints_url"]);
        }

        $this->options = $options;
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthenticationEndpointUrl(Request $request, $redirectUri = 'login_check', array $extraParameters = array())
    {
        $urlParameters = array(
            'client_id' => $this->options['client_id'],
            'response_type' => 'code',
            'redirect_uri' => $this->httpUtils->generateUri($request, $redirectUri),
            'scope' => $this->options['scope'],
            'max_age' => $this->options['authentication_ttl']
        );

        if($this->nonceHelper->isNonceEnabled()) {
            $urlParameters['nonce'] = $this->nonceHelper->buildNonceValue($request->getClientIp());
        }
        
        if($this->nonceHelper->isStateEnabled()) {
            $urlParameters['state'] = $this->nonceHelper->buildNonceValue($request->getClientIp(), "state");
        }
        
        if ($this->options['authentication_ttl'] !== null && $this->options['authentication_ttl'] > 0) {
            $urlParameters['max_age'] = $this->options['authentication_ttl'];
        }

        $parametersToAdd = array('display', 'prompt', 'ui_locales');
        foreach ($parametersToAdd as $param) {
            if (array_key_exists($param, $this->options) && $this->options[$param] !== null) {
                $urlParameters[$param] = $this->options[$param];
            }
        }

        $urlParameters = array_merge($urlParameters, $extraParameters);

        $httpRequest = new Request();
        $authenticationUri = $httpRequest->create(
                        $this->options['authorization_endpoint_url'], RequestInterface::METHOD_GET, $urlParameters)
                ->getUri();

        return $authenticationUri;
    }

    /**
     * {@inheritDoc}
     */
    public function getTokenEndpointUrl()
    {
        return $this->options['token_endpoint_url'];
    }

    /**
     * {@inheritDoc}
     */
    public function getUserinfoEndpointUrl()
    {
        return $this->options['userinfo_endpoint_url'];
    }

    /**
     * {@inheritDoc}
     */
    public function authenticateUser(Request $request)
    {   
        $this->responseHandler->hasError($request->query->all());

        $code = $request->query->get('code');

        $oicToken = new OICToken();

        $this->getIdTokenAndAccessToken($request, $oicToken, $code);

        return $oicToken;
    }

    /**
     * Call the OpenID Connect Provider to exchange a code value against an id_token and an access_token
     * 
     * @see http://openid.net/specs/openid-connect-basic-1_0.html#ObtainingTokens
     * 
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken $oicToken
     * @param type $code
     */
    protected function getIdTokenAndAccessToken(Request $request, OICToken $oicToken, $code)
    {
        $this->nonceHelper->checkStateAndNonce($request);

        $postParameters = array(
            'grant_type' => 'authorization_code',
            'code' => $code
        );
        
        $this->retrieveIdTokenAndAccessToken($oicToken, $postParameters);
    }
    
    /**
     * Call the OpenID Connect Provider to exchange a refresh_token value against an id_token and an access_token
     * 
     * @param \Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken $oicToken
     */
    protected function refreshToken(OICToken $oicToken)
    {
        $postParameters = array(
            'grant_type' => 'refresh_token',
            'refresh_token' => $oicToken->getRefreshToken()
        );
        
        $this->retrieveIdTokenAndAccessToken($oicToken, $postParameters);
    }
    
    /**
     * makes the request to the OpenID Connect Provider for get back an Access Token and an ID Token
     * 
     * @param \Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken $oicToken
     * @param type $parameters
     * @throws InvalidIdTokenException
     */
    private function retrieveIdTokenAndAccessToken(OICToken $oicToken, $parameters, $redirectUri = 'login_check')
    {
       
        $parameters['redirect_uri'] = $this->httpUtils->generateUri(new Request(), $redirectUri);
        
        $postParametersQuery = http_build_query($parameters);
        
        $headers = array(
            'User-Agent: WaldoOICRelyingPartyhBundle',
            'Content-Type: application/x-www-form-urlencoded',
            'Content-Length: ' . strlen($postParametersQuery)
        );

        $request = new HttpClientRequest(RequestInterface::METHOD_POST, $this->getTokenEndpointUrl());
        $request->setHeaders($headers);
        $request->setContent($postParametersQuery);

                
        $response = new HttpClientResponse();
        
        $this->httpClient->setOption(CURLOPT_USERPWD, $this->options['client_id'] . ':' . $this->options['client_secret']);
        $this->httpClient->send($request, $response);
        
        $content = $this->responseHandler->handleTokenAndAccessTokenResponse($response);            
        
        // Apply validation describe here: http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
        $this->idTokenValidator->setIdToken($content['id_token']);
        if (!$this->idTokenValidator->isValid()) {

            $errors = sprintf("%s", implode(", ", $this->idTokenValidator->getErrors()));
            
            if($this->logger !== null) {
                $this->logger->error("InvalidIdTokenException " . $errors, $content);
            }
            
            throw new InvalidIdTokenException($errors);
            
        }
        
        $oicToken->setRawTokenData($content);
    }

    
    /**
     * Call the OpenId Connect Provider to get userinfo against an access_token
     * 
     * @see http://openid.net/specs/openid-connect-basic-1_0.html#UserInfo
     * 
     * @param \Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken $oicToken
     */
    public function getEndUserinfo(OICToken $oicToken)
    {
        $this->idTokenValidator->setIdToken($oicToken->getIdToken());
        if(!$this->idTokenValidator->isValid()) {
            if($oicToken->getRefreshToken()) {
                $this->refreshToken($oicToken);
            } else {
                throw new AuthenticationServiceException("The ID Token has expired, we can't get End User info");
            }
        }

        if ($oicToken->getAccessToken() === null) {
            throw new InvalidRequestException("no such access_token");
        }

        $headers = array(
            'Authorization: Bearer ' . $oicToken->getAccessToken()
        );

        $request = new HttpClientRequest(
                ($this->options['enduserinfo_request_method'] == RequestInterface::METHOD_POST
                ? RequestInterface::METHOD_POST
                : RequestInterface::METHOD_GET),
                $this->getUserinfoEndpointUrl());

        $request->setHeaders($headers);

        $response = new HttpClientResponse();
        
        $this->httpClient->send($request, $response);

        $content = $this->responseHandler->handleEndUserinfoResponse($response);

        // Check if the sub value return by the OpenID connect Provider is the 
        // same as previous. If Not, that isn't good...
        if ($content['sub'] !== $oicToken->getIdToken()->claims['sub']) {
            if($this->logger !== null) {
                $this->logger->error("InvalidIdTokenException", $oicToken);
            }
            
            throw new InvalidIdTokenException("The sub value is not equal");
        }
        
        $oicToken->setRawUserinfo($content);
        

        return $content;
    }

}
