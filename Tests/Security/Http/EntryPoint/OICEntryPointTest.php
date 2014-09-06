<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Tests\Security\Http\EntryPoint;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Http\EntryPoint\OICEntryPoint;

/**
 * OICEntryPoint
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICEntryPointTest extends \PHPUnit_Framework_TestCase
{
     public function testStart()
    {
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');

        $httpUtils = $this->getMock('Symfony\Component\Security\Http\HttpUtils');
        $httpUtils->expects($this->once())
                ->method("createRedirectResponse")
                ->with($this->equalTo($request), $this->equalTo("someUri"))
                ->willReturn("realUri")
                ;

        $ResourceOwner = $this->getMock('Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\ResourceOwnerInterface');
        $ResourceOwner->expects($this->once())
                ->method("getAuthenticationEndpointUrl")
                ->with($this->equalTo($request))
                ->willReturn("someUri")
                ;
                
        $entryPoint = new OICEntryPoint($httpUtils, $ResourceOwner);
                
        $response = $entryPoint->start($request, null);

        $this->assertEquals('realUri', $response);
    }
}
