<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Provider;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * OICProvider
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;
    
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }
    
    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if($user->getUsername() === $token->getUsername()) {
                        
            $relodedToken = new OICToken($user->getRoles());
            $relodedToken->setAccessToken($token->getAccessToken());
            $relodedToken->setIdToken($token->getIdToken());
            $relodedToken->setRefreshToken($token->getRefreshToken());
            $relodedToken->setUser($token->getUser());
            
            return $relodedToken;
        }
        
        throw new AuthenticationException('The OpenID Connect authentication failed.');
    }

    /**
     * {@inheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OICToken;
    }

}
