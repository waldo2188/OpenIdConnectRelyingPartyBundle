<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception;

/**
 * InvalidAuthorizationCodeException
 *
 */
class InvalidIdTokenException extends \InvalidArgumentException
{
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'Invalid ID Token.';
    }
}
