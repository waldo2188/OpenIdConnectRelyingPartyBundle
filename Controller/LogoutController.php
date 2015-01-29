<?php

namespace Waldo\OpenIdConnect\RelyingPartyBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class LogoutController extends Controller
{
    public function logoutAction(Request $request)
    {
        return $this->get('waldo_oic_rp.logout')->logout($request);
    }
    
    
}
