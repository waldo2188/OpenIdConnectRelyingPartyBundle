<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Tests\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Yaml\Parser;
use Waldo\OpenIdConnect\RelyingPartyBundle\DependencyInjection\WaldoOpenIdConnectRelyingPartyExtension;

/**
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class WaldoOpenIdConnectRelyingPartyExtensionTest extends \PHPUnit_Framework_TestCase
{

    public function testDefault()
    {
        $container = new ContainerBuilder();
        $loader = new WaldoOpenIdConnectRelyingPartyExtension();
        $config = array($this->getFullConfig());
        $loader->load(array($this->getFullConfig()), $container);
        
        $definitionArray = array(
            "waldo_oic_rp.authentication.listener",
            "waldo_oic_rp.authentication.provider",
            "waldo_oic_rp.authentication.entrypoint",
            "waldo_oic_rp.validator.id_token",
            "waldo_oic_rp.http_client_response_handler",
            "waldo_oic_rp.jwk_handler",
            "waldo_oic_rp.helper.nonce",
            "waldo_oic_rp.user.provider",
            "waldo_oic_rp.abstract_resource_owner.generic",
            "buzz.client",
            "waldo_oic_rp.http_client",
            "waldo_oic_rp.resource_owner.generic"
        );

        foreach($definitionArray as $definition) {
            $this->assertTrue($container->hasDefinition($definition));
        }
        
        $this->assertEquals('waldo_oic_rp', $loader->getAlias());
    }

    
    protected function getFullConfig()
    {
        $yaml = <<<EOF
base_url: http://base-url.com
client_id: my_client_id
client_secret: my_client_secret
issuer: http://issuer.com
token_ttl: 1
authentication_ttl: 2
ui_locales: FR_fr
display: page
prompt: login
scope: openid
endpoints_url:
    authorization: /auth
    token: /token
    userinfo: /userinfo
http_client:
    timeout: 3
    verify_peer: false
    max_redirects: 4
    ignore_errors: false
    proxy: localhost:8080
jwk_url: http://issuer.com/op.jwk
jwk_cache_ttl: 5
EOF;
        $parser = new Parser();

        return $parser->parse($yaml);
    }

    /**
     * @param mixed $value
     * @param string $key
     */
    private function assertParameter($value, $key)
    {
        $this->assertEquals($value, $this->containerBuilder->getParameter($key), sprintf('%s parameter is correct', $key));
    }
    
}
        