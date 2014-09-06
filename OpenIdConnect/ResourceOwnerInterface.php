<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect;

use Symfony\Component\HttpFoundation\Request;

/**
 * ResourceOwnerInterface
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
interface ResourceOwnerInterface
{

    /**
     * Returns the provider's authorization url
     *
     * @param string $redirectUri The uri to redirect the client back to
     * @param array $extraParameters An array of parameters to add to the url
     *
     * @return string The authorization url
     */
    public function getAuthenticationEndpointUrl(Request $request, $redirectUri = null, array $extraParameters = array());

    /**
     * 
     * @return string The token endpoint url
     */
    public function getTokenEndpointUrl();

    /**
     * @return string The userinfo endpoint url
     */
    public function getUserinfoEndpointUrl();

    /**
     * Check if user is already authenticated
     * 
     * @return Symfony\Component\Security\Core\Authentication\Token\TokenInterface | boolean
     */
    public function isAuthenticated();

    /**
     * Use the code parameter set in request query for retrieve the enduser informations
     * 
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken
     */
    public function authenticateUser(Request $request);

    /**
     * Return a name for the resource owner.
     *
     * @return string
     */
    public function getName();
}
