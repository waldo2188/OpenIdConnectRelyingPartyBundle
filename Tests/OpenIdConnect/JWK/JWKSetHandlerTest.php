<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Tests\JWK;

use Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\JWK\JWKSetHandler;
use Waldo\OpenIdConnect\RelyingPartyBundle\Tests\Mocks\HttpClientMock;
use Buzz\Message\RequestInterface;
/**
 * JWKSetHandler
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class JWKSetHandlerTest extends \PHPUnit_Framework_TestCase
{

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        self::clearCache();
    }


    public static function tearDownAfterClass()
    {
        parent::tearDownAfterClass();
        self::clearCache();
    }


    private static function clearCache()
    {
        $folder = sys_get_temp_dir() . "/waldo/OIC/jwk-cache/";

        $fs = new \Symfony\Component\Filesystem\Filesystem();

        if(is_file($folder . "op.jwk")) {
            unlink($folder . "op.jwk");
        }

        $fs->remove(sys_get_temp_dir() . "/waldo");

    }

    public function testGetJwkShoulReturnFalse()
    {
        $httpClient = new HttpClientMock();
        $jWKSetHandler = new JWKSetHandler(null, 1, "", $httpClient);

        $this->assertFalse($jWKSetHandler->getJwk());
    }

    public function testGetJwk()
    {
        $expected = array("text" => "some content");

        $httpClient = new HttpClientMock();
        $httpClient->setResponseContent(true,
                array(
                    "HTTP/1.1 200 OK",
                    "Content-Type: application/json",
                ),
                json_encode($expected));
        $jWKSetHandler = new JWKSetHandler("http://some.where", 1, sys_get_temp_dir(), $httpClient);

        $res = (array) $jWKSetHandler->getJwk();

        $this->assertEquals("http://some.where", $httpClient->getRequest()->getResource());
        $this->assertEquals(RequestInterface::METHOD_GET, $httpClient->getRequest()->getMethod());
        $this->assertEquals($expected, $res);
    }

    /**
     * @depends testGetJwk
     */
    public function testGetJwkCacheExist()
    {
        $expected = array("text" => "some content");

        $httpClient = new HttpClientMock();
        $httpClient->setResponseContent(true,
                array(
                    "HTTP/1.1 200 OK",
                    "Content-Type: application/json",
                ),
                json_encode($expected));
        $jWKSetHandler = new JWKSetHandler("http://some.where", 30000, sys_get_temp_dir(), $httpClient);

        $res = (array) $jWKSetHandler->getJwk();

        $this->assertNull($httpClient->getRequest());
        $this->assertEquals($expected, $res);
    }

}
