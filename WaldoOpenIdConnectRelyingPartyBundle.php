<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Waldo\OpenIdConnect\RelyingPartyBundle\DependencyInjection\WaldoOpenIdConnectRelyingPartyExtension;
use Waldo\OpenIdConnect\RelyingPartyBundle\DependencyInjection\Security\Factory\OICFactory;

class WaldoOpenIdConnectRelyingPartyBundle extends Bundle
{

    /**
     * {@inheritDoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new OICFactory());
    }

    /**
     * {@inheritdoc}
     */
    public function getContainerExtension()
    {
        // return the right extension instead of "auto-registering" it. Now the
        // alias can be waldo_oic_rp instead of waldo_open_id_connect_relying_party..
        if (null === $this->extension) {
            return new WaldoOpenIdConnectRelyingPartyExtension();
        }
        return $this->extension;
    }

}
