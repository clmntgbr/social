<?php

namespace App\Controller\Auth\Social;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

/**
 * @Route("/authentication")
 */
class AuthenticationLinkedinController extends AbstractController
{
    /**
     * @Route("/linkedin", name="authentication_linkedin")
     */
    public function connectAction(ClientRegistry $clientRegistry)
    {
        return $clientRegistry
            ->getClient('linkedin')
            ->redirect([], []);
    }

    /**
     * @Route("/linkedin/callback", name="authentication_linkedin_callback")
     */
    public function connectCallbackAction(Request $request, ClientRegistry $clientRegistry)
    {
        return $this->redirectToRoute('app_dashboard');
    }
}
