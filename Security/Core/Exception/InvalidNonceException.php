<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception;

/**
 * InvalidAuthorizationCodeException
 *
 */
class InvalidNonceException extends \InvalidArgumentException
{   
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'Invalid nonce code.';
    }
}
