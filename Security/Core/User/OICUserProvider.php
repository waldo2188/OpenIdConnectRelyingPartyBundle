<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User\OICUser;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * OICUserProvider
 *
 */
class OICUserProvider implements UserProviderInterface
{
    /**
     * {@inheritDoc}
     */
    public function loadUserByUsername($username)
    {       
        return new OICUser($username);
    }

    /**
     * {@inheritDoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('Unsupported user class "%s"', get_class($user)));
        }
       
        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function supportsClass($class)
    {
        return $class === 'Waldo\\OpenIdConnect\\RelyingPartyBundle\\Security\\Core\\User\\OICUser';
    }
}
