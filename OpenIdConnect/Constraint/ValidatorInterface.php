<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Constraint;

/**
 * ValidatorInterface
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
interface ValidatorInterface
{
    /**
     * @param mix $value
     * @return boolean
     */
    public function isValid($value);
}
