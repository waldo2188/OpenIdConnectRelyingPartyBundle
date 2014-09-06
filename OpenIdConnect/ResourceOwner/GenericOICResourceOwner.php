<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwner;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwner\AbstractGenericOICResourceOwner;

/**
 * GenericOICResourceOwner
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class GenericOICResourceOwner extends AbstractGenericOICResourceOwner
{

    /**
     * {@inheritDoc}
     */
    public function getName()
    {
        return "generic";
    }

}
