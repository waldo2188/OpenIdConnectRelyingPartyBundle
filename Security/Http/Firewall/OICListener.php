<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Http\Firewall;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwnerInterface;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * OpenId Connect Listener
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICListener extends AbstractAuthenticationListener
{
    /**
     * @var SecurityContext 
     */
    private $securityContext;

    /**
     * @var ResourceOwnerInterface  
     */
    private $resourceOwner;

    /**
     * @param ResourceOwnerInterface $resourceOwner
     */
    public function setResourceOwner(ResourceOwnerInterface $resourceOwner)
    {
        $this->resourceOwner = $resourceOwner;
    }
    
    /**
     * @param \Symfony\Component\Security\Core\SecurityContext $securityContext
     */
    public function setSecurityContext(SecurityContext $securityContext)
    {
        $this->securityContext = $securityContext;
    }

    
    /**
     * {@inheritDoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        if ($this->securityContext->getToken() && $this->securityContext->getToken()->isAuthenticated()) {
            return $this->securityContext->getToken();
        }

        if ($request->query->count() == 0) {
            $uri = $this->resourceOwner->getAuthenticationEndpointUrl($request);
            return new RedirectResponse($uri);
        }
        
        $oicToken = $this->resourceOwner->authenticateUser($request);
        
        return $this->authenticationManager->authenticate($oicToken);
    }

}
