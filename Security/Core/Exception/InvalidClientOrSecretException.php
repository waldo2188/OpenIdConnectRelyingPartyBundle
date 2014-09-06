<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception;


/**
 * InvalidClientOrSecretException
 *
 */
class InvalidClientOrSecretException extends \InvalidArgumentException
{
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'Invalid client_id or client_secret.';
    }
}
