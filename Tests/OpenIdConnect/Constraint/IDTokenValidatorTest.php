<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Tests\Constraint;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Constraint\IDTokenValidator;

/**
 * IDTokenValidatorTest
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class IDTokenValidatorTest extends \PHPUnit_Framework_TestCase
{

    private $options = array(
        "issuer" => "anIssuer",
        "client_id" => "anclient_id",
        "token_ttl" => 3600,
        "authentication_ttl" => 3600
    );
    private $token;

    public function setUp()
    {
        $this->token = array(
            "claims" => array(
                "iss" => "anIssuer",
                "aud" => "anclient_id",
                "azp" => "anclient_id",
                "exp" => (time() + 3600),
                "iat" => time(),
                "auth_time" => time()
            )
        );
    }

    public function testAllSouldBeGood()
    {
        $validator = new IDTokenValidator($this->options);

        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertTrue($res);
    }
    
    public function testAllSouldBeGoodWithoutTime()
    {
        $this->options['authentication_ttl'] = null;
        $validator = new IDTokenValidator($this->options);
        
        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertTrue($res);
    }
    
    public function testAllSouldNotFailWithoutTime()
    {
        unset($this->token['claims']['auth_time']);
        
        $validator = new IDTokenValidator($this->options);
        
        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertTrue($res);
    }
    
    public function testAllSouldBeGoodAud()
    {
        $this->token["claims"]['aud'] = array('anclient_id', "anclient_id2");

        $validator = new IDTokenValidator($this->options);

        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertTrue($res);
    }
    
    public function testAllSouldBeGoodAudSecond()
    {
        $this->token["claims"]['aud'] = array('anclient_id');

        $validator = new IDTokenValidator($this->options);

        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertTrue($res);
    }
    
    public function testAllSouldFaildAtIssuer()
    {
        $this->options['issuer'] = 'fake';
        $validator = new IDTokenValidator($this->options);

        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertFalse($res);
    }
    
    public function testAllSouldFaildAtClient()
    {
        $this->token["claims"]['aud'] = new IDTokenValidator($this->options);
        $this->token["claims"]['azp'] = new IDTokenValidator($this->options);
        $validator = new IDTokenValidator($this->options);

        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertFalse($res);
    }
    
    public function testAllSouldFaildAtAzp()
    {
        $this->token["claims"]['aud'] = array('anclient_id', "anclient_id2");
        unset($this->token["claims"]['azp'] );
        $validator = new IDTokenValidator($this->options);

        $validator->setIdToken($this->token);
        
        $res = $validator->isValid();
        $this->assertFalse($res);
    }

}
