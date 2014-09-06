<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Http\Firewall;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwnerInterface;
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
     * {@inheritDoc}
     */
    protected function attemptAuthentication(Request $request) {

        if($token = $this->resourceOwner->isAuthenticated()) {
            return $token;
        }
        
        if ($request->query->count() == 0) {
            $uri = $this->resourceOwner->getAuthenticationEndpointUrl($request);
            return new RedirectResponse($uri);
        }

        return $this->resourceOwner->authenticateUser($request);
    }

}
