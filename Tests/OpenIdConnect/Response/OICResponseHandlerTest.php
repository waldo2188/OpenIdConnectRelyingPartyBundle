<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Tests\Response;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Response\OICResponseHandler;

/**
 * OICResponseHandler
 * @group OICResponseHandler
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICResponseHandlerTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @expectedException Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidRequestException
     * @expectedExceptionMessage invalid request
     */
    public function testHandleHttpClientResponseBearerError()
    {
        $response = new \Buzz\Message\Response();
        
        $header = array(
            "HTTP/1.0 400 Bad Request",
            'WWW-Authenticate: Bearer error="invalid request", error_description="an error description"',
            "Content-Type: text/html");
        $response->addHeaders($header);

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $oicResponseHandler->handleHttpClientResponse($response);    

    }
    
    /**
     * @expectedException Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidRequestException
     * @expectedExceptionMessage Secured Area
     */
    public function testHandleHttpClientBasicAuthFailError()
    {
        $response = new \Buzz\Message\Response();

        $header = array(
            "HTTP/1.0 401 Unauthorized",
            'WWW-Authenticate: Basic realm="Secured Area"',
            "Content-Type: text/html");
        $response->addHeaders($header);

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $oicResponseHandler->handleHttpClientResponse($response);    

    }

    /**
     * @expectedException Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidRequestException
     * @expectedExceptionMessage bumber
     */
    public function testHandleUnknowError()
    {
        $response = new \Buzz\Message\Response();
        
        $header = array(
            "HTTP/1.0 400 Bad Request",
            "Content-Type: application/json");
        $response->addHeaders($header);
        $response->setContent('{"error":"bumb","error_description":"bumber"}');

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $oicResponseHandler->handleHttpClientResponse($response);    

    }

    /**
     * @expectedException Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidRequestException
     * @expectedExceptionMessage bumb
     */
    public function testHandleErrorWhithoutDescription()
    {
        $response = new \Buzz\Message\Response();
        
        $header = array(
            "HTTP/1.0 400 Bad Request",
            "Content-Type: application/json");
        $response->addHeaders($header);
        $response->setContent('{"error":"bumb"}');

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $oicResponseHandler->handleHttpClientResponse($response);    


    }
    
    
    /**
     * @expectedException Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidAuthorizationCodeException
     */
    public function testHandleHttpClientResponseInvalidAutorizationCode()
    {
        $response = new \Buzz\Message\Response();
        
        $header = array(
            "HTTP/1.0 400 Bad Request",
            "Content-Type: application/json");
        $response->addHeaders($header);
        $response->setContent('{"error":"invalid_authorization_code","error_description":"no such code"}');

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $oicResponseHandler->handleHttpClientResponse($response);    
    }
    
    /**
     * @dataProvider tokendataProvider
     */
    public function testHandleTokenAndAccessTokenResponseShouldBeOk($alg, $token, $jwkWithoutUse = false)
    {
        $response = new \Buzz\Message\Response();
        
        $header = array("HTTP/1.1 200 OK", "Content-Type: application/json");
        $response->addHeaders($header);

        $response->setContent($token);

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler($jwkWithoutUse), array());
        
        $res = $oicResponseHandler->handleTokenAndAccessTokenResponse($response);
        
        $this->assertEquals('Q5GBZL9RmntEZDd88', $res['access_token']);
        $this->assertEquals('Bearer', $res['token_type']);
        $this->assertEquals('3600', $res['expires_in']);
        $this->assertInstanceOf('JOSE_JWT', $res['id_token']);
        
        if($alg != null) {
            $this->assertEquals("http://localhost/phpOp/op.jwk", $res['id_token']->header['jku']);
        }
        $this->assertEquals("1a08411743e829c787a0152d004c6d48a14e921ed5023a65bb39ad72661cca78", $res['id_token']->claims['sub']);
    }
    
    public function tokendataProvider()
    {
        return array(
            array("alg" => null, "token" => '{"access_token":"Q5GBZL9RmntEZDd88","token_type":"Bearer","expires_in":3600,"id_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOlxcXFwvXFxcXC9sb2NhbGhvc3RcXFxcL3BocE9wIiwic3ViIjoiMWEwODQxMTc0M2U4MjljNzg3YTAxNTJkMDA0YzZkNDhhMTRlOTIxZWQ1MDIzYTY1YmIzOWFkNzI2NjFjY2E3OCIsImF1ZCI6WyJteV9jbGllbnRfaWQiXSwiZXhwIjoxNDA5OTk4NDY4LCJpYXQiOjE0MDk5OTgxNjgsIm5vbmNlIjoiWTJKbFl6VTJZbVZtTmpSbU5XWmlZMk14TURBeU56RTBPR1ZsTmpjM01tUXRUVlJKTTB4cVFYVk5RelI0IiwiYXV0aF90aW1lIjoxNDA5OTk0ODM5fQ."}'),
            array("alg" => 'RS256', "token" => '{"access_token":"Q5GBZL9RmntEZDd88","token_type":"Bearer","expires_in":3600,"id_token":"eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6XC9cL2xvY2FsaG9zdFwvcGhwT3BcL29wLmp3ayIsImtpZCI6IlBIUE9QLTAwIn0.eyJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3RcL3BocE9wIiwic3ViIjoiMWEwODQxMTc0M2U4MjljNzg3YTAxNTJkMDA0YzZkNDhhMTRlOTIxZWQ1MDIzYTY1YmIzOWFkNzI2NjFjY2E3OCIsImF1ZCI6WyJteV9jbGllbnRfaWQiXSwiZXhwIjoxNDA5OTk1NzM5LCJpYXQiOjE0MDk5OTU0MzksIm5vbmNlIjoiWlRreE9HSTNNamxsTkRBd00yRXhZMkZrWXpSbE5UUTBaalF6TmpFNE9URXRUVlJKTTB4cVFYVk5RelI0IiwiYXRfaGFzaCI6IjZaVVJUeFpEdGtSU2M5ZXlTNUxOSlEiLCJhdXRoX3RpbWUiOjE0MDk5OTQ4Mzl9.b2H0jQ0GFSB4XyFBN4Ktj8Jr6i64FEMw4V9bVATl3gaIIFCJ0D0EHLD2isQde-so7KGzfw2X3Vvc52Y2cMHwnbx9FInWInOHGSnxZXM6YjmQB05GMB_lpSmnPfsz0DR5q5ZVPiG2xaIrbBqJlsFFBr2znvE3I5tlWJYCPzK2lOA"}'),
            array("alg" => 'RS256', "token" => '{"access_token":"Q5GBZL9RmntEZDd88","token_type":"Bearer","expires_in":3600,"id_token":"eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6XC9cL2xvY2FsaG9zdFwvcGhwT3BcL29wLmp3ayIsImtpZCI6IlBIUE9QLTAwIn0.eyJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3RcL3BocE9wIiwic3ViIjoiMWEwODQxMTc0M2U4MjljNzg3YTAxNTJkMDA0YzZkNDhhMTRlOTIxZWQ1MDIzYTY1YmIzOWFkNzI2NjFjY2E3OCIsImF1ZCI6WyJteV9jbGllbnRfaWQiXSwiZXhwIjoxNDA5OTk1NzM5LCJpYXQiOjE0MDk5OTU0MzksIm5vbmNlIjoiWlRreE9HSTNNamxsTkRBd00yRXhZMkZrWXpSbE5UUTBaalF6TmpFNE9URXRUVlJKTTB4cVFYVk5RelI0IiwiYXRfaGFzaCI6IjZaVVJUeFpEdGtSU2M5ZXlTNUxOSlEiLCJhdXRoX3RpbWUiOjE0MDk5OTQ4Mzl9.b2H0jQ0GFSB4XyFBN4Ktj8Jr6i64FEMw4V9bVATl3gaIIFCJ0D0EHLD2isQde-so7KGzfw2X3Vvc52Y2cMHwnbx9FInWInOHGSnxZXM6YjmQB05GMB_lpSmnPfsz0DR5q5ZVPiG2xaIrbBqJlsFFBr2znvE3I5tlWJYCPzK2lOA"}', true)
           );            
    }
    
    public function testHandleTokenAndAccessTokenResponseWithEmptyContent()
    {
        $response = new \Buzz\Message\Response();
        
        $header = array("HTTP/1.1 200 OK", "Content-Type: application/json");
        $response->addHeaders($header);
        $response->setContent("");

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $res = $oicResponseHandler->handleTokenAndAccessTokenResponse($response);
        
        $this->assertNull($res);    
    }
    
    /**
     * @dataProvider enduserataProvider
     */
    public function testHandleEndUserinfoResponseShouldBeOk($headerApplicationType, $alg, $content, $jwkWithoutUse = false)
    {
        $response = new \Buzz\Message\Response();
        
        $header = array("HTTP/1.1 200 OK", "Content-Type: application/" . $headerApplicationType);
        $response->addHeaders($header);
        $response->setContent($content);

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler($jwkWithoutUse), array());
        
        $res = $oicResponseHandler->handleEndUserinfoResponse($response);
        
        $expected = json_decode('{"sub":"1a08411743e829c787a0152d004c6d48a14e921ed5023a65bb39ad72661cca78","birthdate":"2000-01-01","email":"alice@wonderland.com","email_verified":true,"family_name":"Yamada","gender":"Female","given_name":"Alice","locale":"en","middle_name":"","name":"Alice Yamada","nickname":"Alice Nickname","phone_number":"123-456-7890","phone_number_verified":true,"picture":"http:\/\/localhost\/phpOp\/profiles\/smiling_woman.jpg","preferred_username":"AlicePreferred","profile":"http:\/\/www.wonderland.com\/alice","updated_at":"1408441944","website":"http:\/\/www.wonderland.com","zoneinfo":"america\/Los Angeles"}', true);
                
        $this->assertEquals($expected, $res);
    }
    
    public function enduserataProvider()
    {
        return array(
            array("headerApplicationType" => "json", "alg" => null, "content" => '{"sub":"1a08411743e829c787a0152d004c6d48a14e921ed5023a65bb39ad72661cca78","birthdate":"2000-01-01","email":"alice@wonderland.com","email_verified":true,"family_name":"Yamada","gender":"Female","given_name":"Alice","locale":"en","middle_name":"","name":"Alice Yamada","nickname":"Alice Nickname","phone_number":"123-456-7890","phone_number_verified":true,"picture":"http:\/\/localhost\/phpOp\/profiles\/smiling_woman.jpg","preferred_username":"AlicePreferred","profile":"http:\/\/www.wonderland.com\/alice","updated_at":"1408441944","website":"http:\/\/www.wonderland.com","zoneinfo":"america\/Los Angeles"}'),
            array("headerApplicationType" => "jwt", "alg" => 'RS256', "content" => 'eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6XC9cL2xvY2FsaG9zdFwvcGhwT3BcL29wLmp3ayIsImtpZCI6IlBIUE9QLTAwIn0.eyJzdWIiOiIxYTA4NDExNzQzZTgyOWM3ODdhMDE1MmQwMDRjNmQ0OGExNGU5MjFlZDUwMjNhNjViYjM5YWQ3MjY2MWNjYTc4IiwiYmlydGhkYXRlIjoiMjAwMC0wMS0wMSIsImVtYWlsIjoiYWxpY2VAd29uZGVybGFuZC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmFtaWx5X25hbWUiOiJZYW1hZGEiLCJnZW5kZXIiOiJGZW1hbGUiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJsb2NhbGUiOiJlbiIsIm1pZGRsZV9uYW1lIjoiIiwibmFtZSI6IkFsaWNlIFlhbWFkYSIsIm5pY2tuYW1lIjoiQWxpY2UgTmlja25hbWUiLCJwaG9uZV9udW1iZXIiOiIxMjMtNDU2LTc4OTAiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOnRydWUsInBpY3R1cmUiOiJodHRwOlwvXC9sb2NhbGhvc3RcL3BocE9wXC9wcm9maWxlc1wvc21pbGluZ193b21hbi5qcGciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZVByZWZlcnJlZCIsInByb2ZpbGUiOiJodHRwOlwvXC93d3cud29uZGVybGFuZC5jb21cL2FsaWNlIiwidXBkYXRlZF9hdCI6IjE0MDg0NDE5NDQiLCJ3ZWJzaXRlIjoiaHR0cDpcL1wvd3d3LndvbmRlcmxhbmQuY29tIiwiem9uZWluZm8iOiJhbWVyaWNhXC9Mb3MgQW5nZWxlcyJ9.fnlRGOyXrx1KOi9trHzhX_eOGQqU31445YwFBv8cNHiIcBal1bDyBUmusz4bul5MsG74GJFBahG_jzCtXBnIL8KfccAT2GO46ertW6aRLcKxjLkCiYj28ODe4DewU8Z-F7oMznEooxOOPV-jLlY_XCzNA_K8Bv8GEb_swFPjcGU'),
            array("headerApplicationType" => "jwt", "alg" => 'RS256', "content" => 'eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6XC9cL2xvY2FsaG9zdFwvcGhwT3BcL29wLmp3ayIsImtpZCI6IlBIUE9QLTAwIn0.eyJzdWIiOiIxYTA4NDExNzQzZTgyOWM3ODdhMDE1MmQwMDRjNmQ0OGExNGU5MjFlZDUwMjNhNjViYjM5YWQ3MjY2MWNjYTc4IiwiYmlydGhkYXRlIjoiMjAwMC0wMS0wMSIsImVtYWlsIjoiYWxpY2VAd29uZGVybGFuZC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmFtaWx5X25hbWUiOiJZYW1hZGEiLCJnZW5kZXIiOiJGZW1hbGUiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJsb2NhbGUiOiJlbiIsIm1pZGRsZV9uYW1lIjoiIiwibmFtZSI6IkFsaWNlIFlhbWFkYSIsIm5pY2tuYW1lIjoiQWxpY2UgTmlja25hbWUiLCJwaG9uZV9udW1iZXIiOiIxMjMtNDU2LTc4OTAiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOnRydWUsInBpY3R1cmUiOiJodHRwOlwvXC9sb2NhbGhvc3RcL3BocE9wXC9wcm9maWxlc1wvc21pbGluZ193b21hbi5qcGciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZVByZWZlcnJlZCIsInByb2ZpbGUiOiJodHRwOlwvXC93d3cud29uZGVybGFuZC5jb21cL2FsaWNlIiwidXBkYXRlZF9hdCI6IjE0MDg0NDE5NDQiLCJ3ZWJzaXRlIjoiaHR0cDpcL1wvd3d3LndvbmRlcmxhbmQuY29tIiwiem9uZWluZm8iOiJhbWVyaWNhXC9Mb3MgQW5nZWxlcyJ9.fnlRGOyXrx1KOi9trHzhX_eOGQqU31445YwFBv8cNHiIcBal1bDyBUmusz4bul5MsG74GJFBahG_jzCtXBnIL8KfccAT2GO46ertW6aRLcKxjLkCiYj28ODe4DewU8Z-F7oMznEooxOOPV-jLlY_XCzNA_K8Bv8GEb_swFPjcGU', true)
           );            
    }
    
    /**
     * @expectedException Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidIdSignatureException
     */
    public function testHandleEndUserinfoResponseShouldFail()
    {
        $response = new \Buzz\Message\Response();
        
        $header = array("HTTP/1.1 200 OK", "Content-Type: application/jwt");
        $response->addHeaders($header);
        $response->setContent('eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6XC9cL2xvY2FsaG9zdFwvcGhwT3BcL29wLmp3ayIsImtpZCI6IlBIUE9QLTAwIn0.eyJzdWIiOiIxYTA4NDExNzQzZTgyOWM3ODdhMDE1MmQwMDRjNmQ0OGExNGU5MjFlZDUwMjNhNjViYjM5YWQ3MjY2MWNjYTc4IiwiYmlydGhkYXRlIjoiMjAwMC0wMS0wMSIsImVtYWlsIjoiYWxpY2VAd29uZGVybGFuZC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmFtaWx5X25hbWUiOiJZYW1hZGEiLCJnZW5kZXIiOiJGZW1hbGUiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJsb2NhbGUiOiJlbiIsIm1pZGRsZV9uYW1lIjoiIiwibmFtZSI6IkFsaWNlIFlhbWFkYSIsIm5pY2tuYW1lIjoiQWxpY2UgTmlja25hbWUiLCJwaG9uZV9udW1iZXIiOiIxMjMtNDU2LTc4OTAiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOnRydWUsInBpY3R1cmUiOiJodHRwOlwvXC9sb2NhbGhvc3RcL3BocE9wXC9wcm9maWxlc1wvc21pbGluZ193b21hbi5qcGciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZVByZWZlcnJlZCIsInByb2ZpbGUiOiJodHRwOlwvXC93d3cud29uZGVybGFuZC5jb21cL2FsaWNlIiwidXBkYXRlZF9hdCI6IjE0MDg0NDE5NDQiLCJ3ZWJzaXRlIjoiaHR0cDpcL1wvd3d3LndvbmRlcmxhbmQuY29tIiwiem9uZWluZm8iOiJhbWVyaWNhXC9Mb3MgQW5nZWxlcyJ9.fnlRGOyXrx1KOi9trHzhX_eOGQqU31445YwFBv8cNHiIcBal1bDyBUmusz4bul5MsG74GJFBahG_jzCtXBnIL8KfccAT2GO46ertW6aRLcKxjLkCiYj28ODe4DewU8Z-F7oMznEooxOOPV-jLlY_XCzNA_K8Bv8GEb_swFPjcGU1');

        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        $oicResponseHandler->handleEndUserinfoResponse($response);
    }
    
    /**
     * @dataProvider codeerrorDataProvider
     */
    public function testShoulAlwaysFail($content, $exception)
    {
        $response = new \Buzz\Message\Response();
        
        $header = array("HTTP/1.0 400 Bad Request", "Content-Type: application/json");
        $response->addHeaders($header);
        $response->setContent(json_encode(array(
            'error' => $content,
            'error_description' => "an error description",
        )));
        
        $oicResponseHandler = new OICResponseHandler(
                $this->createJWKSetHandler(),
                array());
        
        try {
            $oicResponseHandler->handleEndUserinfoResponse($response);
        } catch (\Exception $ex) {
            $this->assertInstanceOf($exception, $ex);
            return;
        }
        
        $this->fail('An expected exception has not been raised.');
    }
    
    public function codeerrorDataProvider()
    {
        return array(
            array('content' => 'invalid_response_type', 'exception' => 'Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidResponseTypeException'),
            array('content' => 'invalid_client', 'exception' => 'Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\InvalidClientOrSecretException'),
            array('content' => 'unsupported_grant_type', 'exception' => 'Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Exception\UnsuportedGrantTypeException'),
        );
    }

    

    private function createJWKSetHandler($jwkWithoutUse = false)
    {
        $jwkHandler = $this->getMockBuilder('Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\JWK\JWKSetHandler')
                           ->disableOriginalConstructor()
                           ->getMock();
                   $jwk = ($jwkWithoutUse) ? $this->getJWKWithoutUse() : $this->getJWK();
        
        $jwkHandler->expects($this->any())
                ->method('getJwk')
                ->willReturn($jwk);
        
        return $jwkHandler;
    }
    
    private function getJWK()
    {
        return json_decode(<<<JSON
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "n": "ALyIC8vj1tqEIvAvpDMQfgosw13LpBS9Z2lsMmuaLDNJjN_FKIb-HVR2qtMj7AYC0-wYJhGxJpTXJTVRRDz-zLN7uredNxuhVj76vmU1tfvEN0Xq2INYoWeJ3d9fZtkBgKl7Enfkgz858DLAfZuJzDycOzuZXR5r29zXMDstT5F5",
            "e": "AQAB",
            "kid": "PHPOP-00"
        }
    ]
}
JSON
);
    }
    
    private function getJWKWithoutUse()
    {
        return json_decode(<<<JSON
{
    "keys": [
        {
            "kty": "RSA",
            "n": "ALyIC8vj1tqEIvAvpDMQfgosw13LpBS9Z2lsMmuaLDNJjN_FKIb-HVR2qtMj7AYC0-wYJhGxJpTXJTVRRDz-zLN7uredNxuhVj76vmU1tfvEN0Xq2INYoWeJ3d9fZtkBgKl7Enfkgz858DLAfZuJzDycOzuZXR5r29zXMDstT5F5",
            "e": "AQAB",
            "kid": "PHPOP-00"
}
    ]
}
JSON
);
    }
}
