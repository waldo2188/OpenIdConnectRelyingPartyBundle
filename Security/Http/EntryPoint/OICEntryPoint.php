<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Http\EntryPoint;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwnerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\HttpFoundation\Request;

/**
 * OICEntryPoint
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var HttpUtils
     */
    protected $httpUtils;

    /**
     * @var ResourceOwnerInterface 
     */
    protected $resourceOwner;

    /**
     * @param \Symfony\Component\Security\Http\HttpUtils $httpUtils
     * @param \Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwnerInterface $resourceOwner
     */
    public function __construct(HttpUtils $httpUtils, ResourceOwnerInterface $resourceOwner)
    {
        $this->httpUtils = $httpUtils;
        $this->resourceOwner = $resourceOwner;
    }

    /**
     * {@inheritDoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {   
        $authenticationEndpointUrl = $this->resourceOwner->getAuthenticationEndpointUrl($request);

        //Create and return the redirection request to the OpenId Provider
        return $this->httpUtils->createRedirectResponse($request, $authenticationEndpointUrl);
    }

}
