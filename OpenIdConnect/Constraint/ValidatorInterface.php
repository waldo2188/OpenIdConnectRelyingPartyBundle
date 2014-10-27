<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\OpenIdConnect\Constraint;

/**
 * ValidatorInterface
 *
 * @author valérian Girard <valerian.girard@educagri.fr>
 */
interface ValidatorInterface
{
    /**
     * @param mix $value
     */
    public function setIdToken($value);
    
    /**
     * @return boolean
     */
    public function isValid();
    
    /**
     * @return array
     */
    public function getErrors();

    /**
     * When a max_age request is made, the Client SHOULD check 
     * the auth_time Claim value and request re-authentication if it 
     * determines too much time has elapsed since the last End-User 
     * authentication. 
     * 
     * @return boolean
     */
    public function isValidAuthTime();
}
