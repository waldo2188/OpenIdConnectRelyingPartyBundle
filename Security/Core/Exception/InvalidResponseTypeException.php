<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception;

/**
 * InvalidResponseTypeException
 *
 */
class InvalidResponseTypeException extends \InvalidArgumentException
{
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'Response type used is unknow';
    }
}
