<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Security\Core\User;

use Symfony\Component\Security\Core\User\AdvancedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;

/**
 * OICUser
 *
 * @author 
 */
class OICUser implements AdvancedUserInterface, \Serializable, EquatableInterface
{

    /**
     * @var string
     */
    protected $username;

    /**
     * @var array
     */
    protected $attributes = array();

    /**
     * @param string $username
     */
    public function __construct($username, $attributes = null)
    {
        $this->username = $username;
        $this->attributes = $attributes;
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles()
    {
        return array('ROLE_USER', 'ROLE_OIC_USER');
    }

    public function __get($name)
    {
        if (array_key_exists($name, $this->attributes)) {
            return $this->attributes[$name];
        }
        return null;
    }

    public function __set($name, $value)
    {
        $this->attributes[$name] = $value;
    }

    /**
     * {@inheritDoc}
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * {@inheritDoc}
     */
    public function eraseCredentials()
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function equals(UserInterface $user)
    {
        return $user->getUsername() === $this->username;
    }

    /**
     * {@inheritDoc}
     */
    public function isAccountNonExpired()
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function isAccountNonLocked()
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function isCredentialsNonExpired()
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function isEnabled()
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function isEqualTo(UserInterface $user)
    {
        
    }

    /**
     * {@inheritDoc}
     */
    public function serialize()
    {
        return serialize(array(
            $this->username,
            $this->attributes
        ));
    }

    /**
     * {@inheritDoc}
     */
    public function unserialize($serialized)
    {
        $data = unserialize($serialized);

        list($this->username, $this->attributes) = $data;
    }

    public function __toString()
    {
        return $this->getUsername();
    }

}
