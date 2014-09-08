<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\Authentication\Token;

use Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User\OICUser;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * OpenId Connect Token
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
class OICToken extends AbstractToken
{    
    /**
     * @var array
     */
    protected $rawTokenData;
    
    /**
     * @see http://tools.ietf.org/html/rfc6749#section-1.4
     * @var string
     */
    protected $accessToken;

    /**
     * @see http://tools.ietf.org/html/rfc6749#section-1.5
     * @var string
     */
    protected $refreshToken;

    /**
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     * @var array
     */
    protected $idToken;
    
    /**
     * @var array
     */
    protected $userinfo;

    /**
     * @see http://tools.ietf.org/html/rfc6749#section-4.2.2
     * @see http://tools.ietf.org/html/rfc6749#appendix-A.14
     * @var integer
     */
    private $expiresIn;

    /**
     * @var integer
     */
    private $createdAt;

    /**
     * @param array $roles Roles for the token
     */
    public function __construct(array $roles = array())
    {
        parent::__construct($roles);
    }
    
    
    /**
     * {@inheritDoc}
     */
    public function getCredentials()
    {
        return '';
    }

    /**
     * @param string $accessToken The OAuth access token
     */
    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @param array $idToken The OpenId Connect ID Token
     */
    public function setIdToken($idToken)
    {        
        if($this->getUser() === null) {
            $this->setUser(new OICUser($idToken->claims['sub']));
        }
        
        $this->idToken = $idToken;
    }

    /**
     * @return array The OpenId Connect ID Token
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return string the raw token data
     */
    public function getRawTokenData()
    {
        return $this->rawTokenData;
    }

    /**
     * @param array $token The OAuth + OpenID Connect token
     */
    public function setRawTokenData($token)
    {
        if (is_array($token)) {
            
            $this->rawTokenData = $token;
            
            if (array_key_exists('access_token', $token)) {
                $this->accessToken = $token['access_token'];
            }

            if (array_key_exists('refresh_token', $token)) {
                $this->refreshToken = $token['refresh_token'];
            }

            if (array_key_exists('expires_in', $token)) {
                $this->setExpiresIn($token['expires_in']);
            }

            if (array_key_exists('id_token', $token)) {
                $this->setIdToken($token['id_token']);
            }
            
            return;
        }
    }
    
    public function setRawUserinfo($rowData)
    {
        $user = new OICUser($rowData['sub'], $rowData);
        $this->userinfo = $rowData;
        $this->setUser($user);
    }
    
    public function getUserinfo($key = null)
    {
        if($key !== null) {
            if (array_key_exists($key, $this->userinfo)) {
                return $this->userinfo[$key];
            } else {
                throw new \Exception(sprintf("undefined %s value", $key));
            }
        }
        return $this->userinfo;
    }

    /**
     * @return array
     */
    public function getRawToken()
    {
        return $this->rawToken;
    }

    /**
     * @param string $refreshToken The OAuth refresh token
     */
    public function setRefreshToken($refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @param integer $expiresIn The duration in seconds of the access token lifetime
     */
    public function setExpiresIn($expiresIn)
    {
        $this->createdAt = time();
        $this->expiresIn = $expiresIn;
    }

    /**
     * @return integer
     */
    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    /**
     * Returns if the `access_token` is expired.
     *
     * @return boolean True if the `access_token` is expired.
     */
    public function isExpired()
    {
        if (null === $this->expiresIn) {
            return false;
        }
        return ($this->createdAt + ($this->expiresIn - time())) < 30;
    }

    /**
     * {@inheritDoc}
     */
    public function serialize()
    {
        return serialize(array(
            $this->idToken,
            $this->accessToken,
            $this->refreshToken,
            $this->expiresIn,
            $this->createdAt,
            parent::serialize()
        ));
    }

    /**
     * {@inheritDoc}
     */
    public function unserialize($serialized)
    {
        $data = unserialize($serialized);
        
        list(
                $this->idToken,
                $this->accessToken,
                $this->refreshToken,
                $this->expiresIn,
                $this->createdAt,
                $parent,
                ) = $data;
        
        parent::unserialize($parent);            
    }

}
