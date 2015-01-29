<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Http\Logout;

use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * OpenId Connect Logout
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICLogout
{
    /**
     * @var TokenStorageInterface 
     */
    private $tokenStorage;

    /**
     * @var HttpUtils  
     */
    private $httpUtils;

    /**
     * @var RouterInterface  
     */
    private $router;

    /**
     * @var array  
     */
    private $options;

    /**
     * @param TokenStorageInterface $tokenStorage
     * @param HttpUtils $httpUtils
     */
    public function __construct(array $options, TokenStorageInterface $tokenStorage, HttpUtils $httpUtils, RouterInterface $router)
    {
        $this->tokenStorage = $tokenStorage;
        $this->httpUtils = $httpUtils;
        $this->router = $router;
        $this->options = $options;  
    }

    
    public function logout(Request $request)
    {
        $request->getSession()->clear();
        $request->getSession()->invalidate();
        $this->tokenStorage->setToken(null);
        
        echo "<pre>:";
        var_dump($request->server->get("HTTP_REFERER"));
        echo "</pre>";exit;



        if($request->server->get("HTTP_REFERER") != $this->httpUtils->generateUri($request, "_oic_rp_logout")) {
            return new RedirectResponse($this->getRedirectAfterLogoutURI($request));
        }
        
        if(array_key_exists("logout", $this->options['endpoints_url'])) {
            return new RedirectResponse($this->getOIDCLogoutEndPointURI($request));
        }        
        
        return new RedirectResponse($this->getRedirectAfterLogoutURI($request));
    }
    
    private function getRedirectAfterLogoutURI(Request $request)
    {
        if($this->router->getRouteCollection()->get($this->options['redirect_after_logout'])) {
            return $this->httpUtils->generateUri($request, $this->options['redirect_after_logout']);
        }
        
        return $this->options['redirect_after_logout'];
    }
    
    
    private function getOIDCLogoutEndPointURI(Request $request)
    {
        return $this->options['endpoints_url']['logout']
                    . "?post_logout_redirect_uri="
                    . urlencode($this->getRedirectAfterLogoutURI($request));
    }
}
