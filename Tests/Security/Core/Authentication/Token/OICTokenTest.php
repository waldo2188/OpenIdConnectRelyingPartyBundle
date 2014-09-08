<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Tests\Security\Core\Authentication\Token;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken;

/**
 * OpenId Connect Token
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICTokenTest extends \PHPUnit_Framework_TestCase
{

    public function testIsAuthnticated()
    {
        $oicToken = new OICToken();
        $this->assertFalse($oicToken->isAuthenticated());

        $oicToken = new OICToken(array("ROLE_FAKE"));
        $this->assertFalse($oicToken->isAuthenticated());
    }

    public function testSetRawTokenDataShouldBeEmpty()
    {
        $oicToken = new OICToken();

        $oicToken->setRawTokenData("some string value");

        $this->assertNull($oicToken->getRawTokenData());
        $this->assertNull($oicToken->getAccessToken());
        $this->assertNull($oicToken->getRefreshToken());
        $this->assertNull($oicToken->getExpiresIn());
        $this->assertNull($oicToken->getIdToken());
    }

    public function testSetRawTokenDataShouldBeSet()
    {
        $oicToken = new OICToken();
        
        $expected = array(
            'access_token' => 'access_token_value',
            'refresh_token' => 'refresh_token_value',
            'expires_in' => 'expires_in_value',
            'id_token' => $this->getIdToken()
        );

        $oicToken->setRawTokenData($expected);

        $this->assertEquals($expected, $oicToken->getRawTokenData());
        $this->assertEquals($expected['access_token'], $oicToken->getAccessToken());
        $this->assertEquals($expected['refresh_token'], $oicToken->getRefreshToken());
        $this->assertEquals($expected['expires_in'], $oicToken->getExpiresIn());
        $this->assertEquals($expected['id_token'], $oicToken->getIdToken());
    }

    public function testUserinfo()
    {
        $userinfo = array(
            'sub' => 'amy.pond',
            'name' => 'Amelia Pond',
            'phone_number' => '123-456-7890'
        );

        $oicToken = new OICToken();

        $oicToken->setRawUserinfo($userinfo);

        $this->assertEquals($oicToken->getUserinfo(), $userinfo);
        $this->assertEquals($oicToken->getUserinfo('phone_number'), $userinfo['phone_number']);
    }

    public function testIsExpired()
    {
        $oicToken = new OICToken();

        $oicToken->setExpiresIn(-30);
        $this->assertTrue($oicToken->isExpired());
        
        $oicToken->setExpiresIn(30);
        $this->assertFalse($oicToken->isExpired());
    }
    
    public function testSerialize()
    {
        $oicToken = new OICToken();

        $expected = array(
            'access_token' => 'access_token_value',
            'refresh_token' => 'refresh_token_value',
            'expires_in' => 'expires_in_value',
            'id_token' => $this->getIdToken()
        );

        $oicToken->setRawTokenData($expected);
        
        $unserialized = unserialize(serialize($oicToken));
        
        $this->assertEquals($expected['access_token'], $unserialized->getAccessToken());
        $this->assertEquals($expected['refresh_token'], $unserialized->getRefreshToken());
        $this->assertEquals($expected['expires_in'], $unserialized->getExpiresIn());
        $this->assertEquals($expected['id_token'], $unserialized->getIdToken());        
    }
    
    private function getIdToken()
    {
        $claims = new \stdClass();
        $claims->claims = array('sub' => "username");
        return $claims;
    }

}
