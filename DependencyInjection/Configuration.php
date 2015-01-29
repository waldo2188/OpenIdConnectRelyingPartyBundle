<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    public static function isHttpMethodSupproted($display)
    {
        $displays = array(
            'POST',
            'GET'
            );
        
        return in_array($display, $displays);
    }
    public static function isDisplaySupproted($display)
    {
        $displays = array(
            'page',
            'popup',
            'touch',
            'wap'
            );
        
        return in_array($display, $displays);
    }
    
    public static function isPromptSupproted($prompt)
    {
        $displays = array(
            'none',
            'login',
            'consent',
            'select_account'
            );
        
        return in_array($prompt, $displays);
    }


    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('waldo_oic_rp');

        $this->addHttpClientConfiguration($rootNode);
        $this->addSignatureConfiguration($rootNode);
        $this->addReplayAttackParadeConfiguration($rootNode);
        
        $rootNode
            ->children()
                ->scalarNode('base_url')->end()
                // URI where the user is redirected after a logout
                ->scalarNode('redirect_after_logout')->defaultNull()->end()
                ->scalarNode('client_id')->cannotBeEmpty()->end()
                ->scalarNode('client_secret')->cannotBeEmpty()->end()
                // issuer is the URL of the OpenId Connect Provider
                // This is needed for validate response of the OpenId Connect Provider
                ->scalarNode('issuer')->cannotBeEmpty()->end()
                // 'token_ttl' value correspond to the iat
                //   Time at which the JWT was issued. Its value is a 
                //   JSON number representing the number of seconds 
                //   from 1970-01-01T0:0:0Z as measured in UTC until the date/time. 
                // Value is stored in second, default 5 minutes
                ->scalarNode('token_ttl')->defaultValue(300)->end()
                // 'authentication_ttl' value correspond to max_age
                //   Maximum Authentication Age. Specifies the allowable elapsed
                //   time in seconds since the last time the End-User was actively
                //   authenticated by the OP. If the elapsed time is greater than
                //   this value, the OP MUST attempt to actively re-authenticate
                //   the End-User. (The max_age request parameter corresponds to
                //   the OpenID 2.0 PAPE [OpenID.PAPE] max_auth_age request parameter.)
                //   When max_age is used, the ID Token returned MUST include
                //   an auth_time Claim Value. 
                // Value is stored in second, default 5 minutes
                ->scalarNode('authentication_ttl')->defaultValue(300)->end()
                // @see http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                ->scalarNode('ui_locales')->end()
                
                // Define the method (POST, GET) used to request the Enduserinfo Endpoint of the OIDC Provider
                ->scalarNode('enduserinfo_request_method')
                        ->validate()
                        ->ifTrue(function($display) {
                            return !Configuration::isHttpMethodSupproted($display);
                        })
                        ->thenInvalid('Unknown request mathod "%s".')
                    ->end()
                    ->defaultValue("POST")->end()
                
                // ASCII string value that specifies how the Authorization Server
                // displays the authentication and consent user interface pages 
                // to the End-User. The defined values are: 
                // @see http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                ->scalarNode('display')
                    ->validate()
                        ->ifTrue(function($display) {
                            return !Configuration::isDisplaySupproted($display);
                        })
                        ->thenInvalid('Unknown display type "%s".')
                    ->end()
                ->end()
                                
                ->scalarNode('prompt')
                    ->validate()
                        ->ifTrue(function($display) {
                            return !Configuration::isPromptSupproted($display);
                        })
                        ->thenInvalid('Unknown prompt type "%s".')
                    ->end()
                ->end()
                
                ->scalarNode('scope')
                    ->validate()
                        ->ifTrue(function($v) {
                            return empty($v);
                        })
                        ->thenUnset()
                    ->end()
                ->end()
            ->end()

            ->children()
                // Endpoints URL are the part of the URL after the OpenId Connect Provider URL
                // If OpenId Connect Provider URL is https://www.myoicop.com/iocp
                // The authorization endpoint configuration is just /authorization 
                ->arrayNode('endpoints_url')
                    ->isRequired()
                        ->children()
                            ->scalarNode('authorization')
                                ->validate()
                                    ->ifTrue(function($v) {
                                        return empty($v);
                                    })
                                    ->thenUnset()
                                ->end()
                            ->end()
                            ->scalarNode('token')
                                ->validate()
                                    ->ifTrue(function($v) {
                                        return empty($v);
                                    })
                                    ->thenUnset()
                                ->end()
                            ->end()
                            ->scalarNode('userinfo')
                                ->validate()
                                    ->ifTrue(function($v) {
                                        return empty($v);
                                    })
                                    ->thenUnset()
                                ->end()
                            ->end()
                            ->scalarNode('logout')
                                ->validate()
                                    ->ifTrue(function($v) {
                                        return empty($v);
                                    })
                                    ->thenUnset()
                                ->end()
                            ->end()
                        ->end()
                ->end()
            ->end()
        ;
                                    
        return $treeBuilder;
    }

    private function addHttpClientConfiguration(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('http_client')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('timeout')->defaultValue(5)->cannotBeEmpty()->end()
                        ->booleanNode('verify_peer')->defaultTrue()->end()
                        ->scalarNode('max_redirects')->defaultValue(5)->cannotBeEmpty()->end()
                        ->booleanNode('ignore_errors')->defaultTrue()->end()
                        ->scalarNode('proxy')->end()
                    ->end()
                ->end()
            ->end()
        ;
    }

    private function addSignatureConfiguration(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                // URL to the Json Web Key
                ->scalarNode('jwk_url')->defaultNull()->end()
                // Validity periods in second where the JWK is valid
                ->scalarNode('jwk_cache_ttl')->defaultValue(86400)->end()
                // @see http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
                ->scalarNode('userinfo_signed_response_alg')->defaultNull()->end()
                ->scalarNode('id_token_signed_response_alg')->defaultNull()->end()
            ->end()
        ;
    }

    private function addReplayAttackParadeConfiguration(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->scalarNode('enabled_state')->defaultTrue()->end()
                ->scalarNode('enabled_nonce')->defaultTrue()->end()
            ->end()
        ;
    }
}
