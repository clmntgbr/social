<?php

namespace App\Controller\Auth\Social;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

/**
 * @Route("/authentication")
 */
class AuthenticationFacebookController extends AbstractController
{
    /**
     * @Route("/facebook", name="authentication_facebook")
     */
    public function connectAction(ClientRegistry $clientRegistry)
    {
        return $clientRegistry
            ->getClient('facebook')
            ->redirect(['public_profile', 'email'], []);
    }

    /**
     * @Route("/facebook/callback", name="authentication_facebook_callback")
     */
    public function connectCallbackAction(Request $request, ClientRegistry $clientRegistry)
    {
        return $this->redirectToRoute('app_dashboard');
    }
}
