<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User;

/**
 * UserFactoryInterface
 *
 * Interface implemented by user providers able to create new users.
 * 
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
interface UserFactoryInterface
{
    /**
* Creates a new user for the given username
*
* @param string $username The username
* @param array $roles Roles assigned to user
* @param array $attributes Attributes provided by OpenID Connect Provider
*
* @return \Symfony\Component\Security\Core\User\UserInterface
*/
public function createUser($username, array $roles, array $attributes);
}
