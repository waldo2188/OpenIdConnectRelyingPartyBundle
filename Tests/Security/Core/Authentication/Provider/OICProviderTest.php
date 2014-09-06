<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Tests\Security\Core\Authentication\Provider;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Provider\OICProvider;


/**
 * OICProvider
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICProviderTest extends \PHPUnit_Framework_TestCase
{
    public function testAuthenticateShoulReturnToken()
    {
        $user = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $user->expects($this->once())
                ->method('getUsername')
                ->willReturn('amy.pond');
        $user->expects($this->once())
                ->method('getRoles')
                ->willReturn(array('ROLE_FAKE'));
        
        $userProvider = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userProvider->expects($this->once())
                ->method('loadUserByUsername')
                ->with($this->equalTo('amy.pond'))
                ->willReturn($user);
        
        $token = $this->getMock('Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken');
        $token->expects($this->exactly(2))
                ->method('getUsername')
                ->willReturn('amy.pond');

        $tokenValue = array(
            'getAccessToken' => 'access',
            'getIdToken' => 'id',
            'getRefreshToken' => 'refresh',
            'getUser' => 'user'
        );
        foreach ($tokenValue as $methode => $returnValue) {
            $token->expects($this->once())
                    ->method($methode)
                    ->willReturn($returnValue);
        }

        $oicProvider = new OICProvider($userProvider);
        
        $resultToken = $oicProvider->authenticate($token);

        $this->assertEquals($tokenValue['getAccessToken'], $resultToken->getAccessToken());
        $this->assertEquals($tokenValue['getRefreshToken'], $resultToken->getRefreshToken());
        $this->assertEquals($tokenValue['getIdToken'], $resultToken->getIdToken());
        $this->assertEquals($tokenValue['getUser'], $resultToken->getUser());
        $this->assertCount(1, $resultToken->getRoles());        
    }
    
    /**
     * @expectedException Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function testAuthenticationShouldFailed()
    {
        $user = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $user->expects($this->once())
                ->method('getUsername')
                ->willReturn('amy.pond');
        
        $userProvider = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userProvider->expects($this->once())
                ->method('loadUserByUsername')
                ->willReturn($user);
        
        $token = $this->getMock('Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token\OICToken');
        $token->expects($this->exactly(2))
                ->method('getUsername')
                ->willReturn('rory.willialms');

        $oicProvider = new OICProvider($userProvider);
        
        $resultToken = $oicProvider->authenticate($token);

    }
}
