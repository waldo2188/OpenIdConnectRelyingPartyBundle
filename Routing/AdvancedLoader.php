<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Routing;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * AdvancedLoader
 * @see http://symfony.com/doc/current/cookbook/routing/custom_route_loader.html
 * 
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class AdvancedLoader implements LoaderInterface
{

    private $loaded = false;

    public function load($resource, $type = null)
    {
        if (true === $this->loaded) {
            throw new \RuntimeException('Do not add the "oic_routing" loader twice');
        }

        $routes = new RouteCollection();

        // prepare a new route
        $path = '/oic-rp/logout';
        $defaults = array(
            '_controller' => 'WaldoOpenIdConnectRelyingPartyBundle:Logout:logout',
        );
        $requirements = array();
        
        $route = new Route($path, $defaults, $requirements);

        // add the new route to the route collection:
        $routeName = '_oic_rp_logout';
        $routes->add($routeName, $route);

        $this->loaded = true;

        return $routes;
    }

    public function supports($resource, $type = null)
    {
        return 'oic_routing' === $type;
    }

    public function getResolver()
    {
        // needed, but can be blank, unless you want to load other resources
        // and if you do, using the Loader base class is easier (see below)
    }

    public function setResolver(LoaderResolverInterface $resolver)
    {
        // same as above
    }
}
