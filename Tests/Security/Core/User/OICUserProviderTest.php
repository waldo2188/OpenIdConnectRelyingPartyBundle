<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Test\Security\Core\User;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User\OICUserProvider;
use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User\OICUser;

class OICUserProviderTest extends \PHPUnit_Framework_TestCase
{

    public function testLoadUserByUsername()
    {
        $oicUserProvider = new OICUserProvider();

        $username = 'amy.pond';

        $oicUser = $oicUserProvider->loadUserByUsername($username);

        $this->assertInstanceOf('Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User\OICUser', $oicUser);
        $this->assertEquals($username, $oicUser->getUsername());
    }

    public function testRefreshUser()
    {
        $oicUserProvider = new OICUserProvider();

        $oicUser = new OICUser('amy.pond');

        $oicUserReturn = $oicUserProvider->refreshUser($oicUser);

        $this->assertEquals($oicUser, $oicUserReturn);
    }

    /**
     * @expectedException Symfony\Component\Security\Core\Exception\UnsupportedUserException
     */
    public function testRefreshUsershouldFail()
    {
        $oicUserProvider = new OICUserProvider();

        $oicUser = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');

        $oicUserReturn = $oicUserProvider->refreshUser($oicUser);
    }

}
