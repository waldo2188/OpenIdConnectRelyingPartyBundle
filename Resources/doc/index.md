OpenID Connect Relying Party Bundle
===================================

## Install
With Composer
Add the code below to your composer.json
```yaml
    "require": {
        "gree/jose": "0.1.7",
        "waldo/openid-connect-relying-party-bundle": "dev-master"
    },
    "repositories": [
        {
            "type": "git",
            "url": "git@github.com:waldo2188/OpenIdConnectRelyingPartyBundle.git"
        },
        {
            "type": "git",
            "url": "git@github.com:waldo2188/jose.git"
        }
    ]
```

## Bundle registration

Register the bundle in the kernel:

``` php
<?php
// app/AppKernel.php

public function registerBundles()
{
    $bundles = array(
        // ...
        new Waldo\OpenIdConnect\RelyingPartyBundle\WaldoOpenIdConnectRelyingPartyBundle(),
    );
}
```

## Configurations
```yaml
#/app/config/config.yml

waldo_oic_rp:
    http_client:                    #Configuration for Buzz
        timeout: 5
        verify_peer: ~
        max_redirects: 5
        proxy: ~
    base_url: http://my-web-site.tld/
    client_id: my_client_id         #OpenID Connect client id given by the OpenId Connect Provider
    client_secret: my_client_secret #OpenID Connect client secret given by the OpenId Connect Provider
    issuer: https://openid-connect-provider.tld #URL of the OpenID Connect Provider
    endpoints_url:                  #Part of the URL of the OpenID Connect Provider
        authorization: /auth
        token: /token
        userinfo: /userinfo
        logout: /logout
    display: page                   #How the authentication form will be display to the enduser
    scope: openid profile email address phone #List of the scope you need
    authentication_ttl: 300         #Maximum age of the authentication
    token_ttl: 300                  #Maximum age for tokenID
    jwk_url: https://openid-connect-provider.tld/op.jwk #URL to the Json Web Key of OpenID Connect Provider
    jwk_cache_ttl 86400             #Validity periods in second where the JWK store in cache is valid
    enabled_state: true             #Enable the use of the state value. This is useful for mitigate replay attack
    enabled_nonce: true             #Enable the use of the nonce value. This is useful for mitigate replay attack
    enduserinfo_request_method: POST#Define the method (POST, GET) used to request the Enduserinfo Endpoint of the OIDC Provider
    redirect_after_logout           #URI or route name used for redirect user after a logout
```

You must add this to your `/app/config/routing.yml`
```yaml
#/app/config/routing.yml
_oic_rp:
    resource: "@WaldoOpenIdConnectRelyingPartyBundle/Resources/config/routing.yml"

#Set a path for the route name 'login_check'
#You don't need to provide a controller for this route
login_check:
    path: /login_check
```


I recommend you to set a path for `default_target_path`. Because you risk to 
suffer redirection loop.
You must maybe set a path for `login_path`, the same as `default_target_path`, 
is a good start.
```yaml
#/app/config/security.yml
security:
    providers:
        OICUserProvider: 
            id: waldo_oic_rp.user.provider
            

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        secured_area:
            pattern: ^/
            anonymous: ~
            openidconnect:
                always_use_default_target_path: false
                default_target_path: /private-page
                login_path: /private-page
                target_path_parameter: ~
                use_referer: ~
                create_users: true              #create user if not found
                created_users_roles: ROLE_OIC_USER #Add this role(s) to new User
    
    access_control:
        - { path: ^/private-page, roles: ROLE_OIC_USER }
        - { path: ^/login$, roles: IS_AUTHENTICATED_ANONYMOUSLY }
```


What is the link for login enduser ?
------------------------------------
Two way to authenticate user.
- The first, do nothing. When an end user come on a page who is behind a firewall,
he will be automatically  redirected to the OpenId Connect Provider's login page
- The second. You can create a login link with the route 'login_check'


How to display a logout link ?
------------------------------
The name of the logout route is `_oic_rp_logout`. You can use it in your Twig template like below : 

```twig
<a href="{{ path('_oic_rp_logout') }}">Logout</a>
```
If you have specified a logout endpoint, the logout mecanisme will proceed of the logout the user on the endpoint.


###TODO
 - Add re-authentication mechanise

###Not yet implemented
#####Client Prepares Authentication Request

http://openid.net/specs/openid-connect-basic-1_0.html#AuthenticationRequest

This options parrameter need to be implemented
 - claims_locales
 - id_token_hint
 - login_hint
 - acr_values


#####ID Token Validation 

http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation

The point 7 is not implemented.
> If the acr Claim was requested, the Client SHOULD check that the asserted Claim 
> Value is appropriate. The meaning and processing of acr Claim Values is out of 
> scope for this document.

