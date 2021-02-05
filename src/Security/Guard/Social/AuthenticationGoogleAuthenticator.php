<?php

namespace App\Security\Guard\Social;

use App\Entity\User\User;
use App\Repository\User\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class AuthenticationGoogleAuthenticator extends SocialAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'authentication_google_callback';

    /** @var ClientRegistry */
    private $clientRegistry;

    /** @var EntityManagerInterface */
    private $entityManager;

    /** @var UserRepository */
    private $userRepository;

    /** @var UserPasswordEncoderInterface */
    private $passwordEncoder;

    /** @var UrlGeneratorInterface  */
    private $urlGenerator;

    public function __construct(UrlGeneratorInterface $urlGenerator, UserPasswordEncoderInterface $passwordEncoder, ClientRegistry $clientRegistry, EntityManagerInterface $entityManager, UserRepository $userRepository)
    {
        $this->clientRegistry = $clientRegistry;
        $this->entityManager = $entityManager;
        $this->userRepository = $userRepository;
        $this->passwordEncoder = $passwordEncoder;
        $this->urlGenerator = $urlGenerator;
    }

    public function supports(Request $request): bool
    {
        return self::LOGIN_ROUTE === $request->attributes->get('_route') && $request->isMethod('GET');
    }

    public function getCredentials(Request $request): AccessToken
    {
        return $this->fetchAccessToken($this->getGoogleClient());
    }

    public function getUser($credentials, UserProviderInterface $userProvider): UserInterface
    {
        $googleUser = $this->getGoogleClient()->fetchUserFromToken($credentials);
        $googleUser = $googleUser->toArray();

        $email = $googleUser['email'];

        $existingUser = $this->userRepository->findOneBy(['googleId' => $googleUser['sub']]);

        if ($existingUser instanceof User) {
            return $existingUser;
        }

        $user = $this->userRepository->findOneBy(['email' => $email]);

        if ($user instanceof User) {
            return $user;
        }

        $user = new User();
        $user->setEmail($email);
        $user->setGoogleId($googleUser['sub']);
        $password = $this->passwordEncoder->encodePassword($user, uniqid());
        $user->setPassword($password);
        $user->setGivenName($googleUser['given_name'] ?? null);
        $user->setFamilyName($googleUser['family_name'] ?? null);
        $user->setLocale($googleUser['locale'] ?? null);
        $user->setEmailVerified($googleUser['email_verified'] ?? null);
        $user->getAvatar()->setName($googleUser['picture'] ?? null);
        $user->getAvatar()->setPath(null);
        $user->getAvatar()->setMimeType(null);
        $user->getAvatar()->setSize(null);
        $user->getAvatar()->setType(null);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    private function getGoogleClient(): OAuth2ClientInterface
    {
        return $this->clientRegistry->getClient('google');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): RedirectResponse
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $providerKey)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('app_dashboard'));
    }

    public function supportsRememberMe(): bool
    {
        return true;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());
        return new Response($message, Response::HTTP_FORBIDDEN);
    }

    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
    {
        return new RedirectResponse(
            '/auth/login',
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }
}