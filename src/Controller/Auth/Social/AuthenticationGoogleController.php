<?php

namespace App\Controller\Auth\Social;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

/**
 * @Route("/Authentication")
 */
class AuthenticationGoogleController extends AbstractController
{
    /**
     * @Route("/google", name="authentication_google")
     */
    public function connectAction(ClientRegistry $clientRegistry)
    {
        return $clientRegistry
            ->getClient('google')
            ->redirect(['profile', 'email'], []);
    }

    /**
     * @Route("/google/callback", name="authentication_google_callback")
     */
    public function connectCallbackAction(Request $request, ClientRegistry $clientRegistry)
    {
        return $this->redirectToRoute('app_dashboard');
    }
}
