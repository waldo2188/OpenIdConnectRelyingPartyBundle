<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

/**
 * OICFactory
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICFactory extends AbstractFactory
{

    public function addConfiguration(\Symfony\Component\Config\Definition\Builder\NodeDefinition $node)
    {
        parent::addConfiguration($node);
        
        $node->children()
                ->scalarNode('create_users')->defaultFalse()->end()
                ->arrayNode('created_users_roles')
                    ->treatNullLike(array())
                    ->beforeNormalization()
                        ->ifTrue(function($v) { return !is_array($v); })
                        ->then(function($v) { return array($v); })
                    ->end()
                    ->prototype('scalar')->end()
                    ->defaultValue(array("ROLE_OIC_USER"))
                ->end()
                
            ->end()
        ;
    }

    
    /**
     * {@inheritDoc}
     */
    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $providerId = 'security.authentication.provider.oic_rp.' . $id;

        $container
                ->setDefinition($providerId, new DefinitionDecorator('waldo_oic_rp.authentication.provider'))
                ->addArgument(new Reference($userProviderId))
                ->addArgument(new Reference('waldo_oic_rp.resource_owner.generic'))
                ->addArgument($config['create_users'])
                ->addArgument($config['created_users_roles'])
        ;

        return $providerId;
    }

    /**
     * {@inheritDoc}
     */
    protected function createEntryPoint($container, $id, $config, $defaultEntryPoint)
    {
        $entryPointId = 'security.authentication.entrypoint.oic_rp.' . $id;

        $container
                ->setDefinition($entryPointId, new DefinitionDecorator('waldo_oic_rp.authentication.entrypoint'))
                ->addArgument(new Reference('waldo_oic_rp.resource_owner.generic'))
        ;

        return $entryPointId;
    }

    /**
     * {@inheritDoc}
     */
    protected function createListener($container, $id, $config, $userProvider)
    {
        $listenerId = parent::createListener($container, $id, $config, $userProvider);

        $container
                ->getDefinition($listenerId)
                ->addMethodCall('setResourceOwner', array(new Reference('waldo_oic_rp.resource_owner.generic')))
                ->addMethodCall('setSecurityContext', array(new Reference('security.context')))
        ;

        return $listenerId;
    }

    /**
     * {@inheritDoc}
     */
    protected function getListenerId()
    {
        return 'waldo_oic_rp.authentication.listener';
    }

    /**
     * {@inheritDoc}
     * Allow to add a custom configuration in a firewall's configuration 
     * in the security.yml file.
     */
    public function getKey()
    {
        return 'openidconnect';
    }

    /**
     * {@inheritDoc}
     */
    public function getPosition()
    {
        return 'pre_auth';
    }

}
