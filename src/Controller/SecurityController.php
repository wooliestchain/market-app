<?php

namespace App\Controller;

use App\Form\ResetPasswordRequestFormType;
use App\Form\ResetPassworFormType;
use App\Repository\UsersRepository;
use App\Service\SendMailService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\TokenGenerator\TokenGeneratorInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route(path: '/connexion', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    #[Route(path: '/deconnexion', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route('/oubli-pass', name: 'forgotten_password')]
    public function forgottenPasseword(Request $request, UsersRepository $usersRepository,
    TokenGeneratorInterface $tokenGenerator,
    EntityManagerInterface $entityManager,
    SendMailService $mail): Response
    {
        $form = $this->createForm(ResetPasswordRequestFormType::class);

        $form->handleRequest($request);

        if($form->isSubmitted() && $form->isValid()){
            //Chercher l'user par son addresse mail
            $user = $usersRepository->findOneByEmail($form->get('email')->getData());

            //Verification de lexstence de l'utilisateur
            if($user){
                //Génération du token pour réinitialiser
                $token = $tokenGenerator->generateToken();
                $user->setResetToken($token);
                $entityManager->persist($user);
                $entityManager->flush();

                //Génération d'un lien de réinitialisation
                $url = $this->generateUrl('reset_pass', ['token' => $token],
                UrlGeneratorInterface::ABSOLUTE_URL);
                //Cre&tion des données du mail
                $context = compact('url', 'user');
                //Envoie du mail
                $mail->send(
                    'no-reply@techshop.fr',
                    $user->getEmail(),
                    'Réinitialistion de mot de passe',
                    'password_reset',
                    $context

                );
                $this->addFlash('success', 'E-mail envoyé');
                return $this->redirectToRoute('app_login');

            }
            $this->addFlash('danger', 'Il y a un soucis');
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/reset_password_request.html.twig', [
            'requestPassForm' => $form->createView()
        ]);
    }

    #[Route('/oubli-pass/{token}', name: 'reset_pass')]
    public function resetPass(string $token, Request $request, UsersRepository $usersRepository,
    EntityManagerInterface $entityManager, UserPasswordHasherInterface $passwordHasher): Response
    {
        //Verifier si le token existe dans la base de données
        $user = $usersRepository->findOneByResetToken($token);

        if($user){
            $form = $this->createForm(ResetPassworFormType::class);

            $form->handleRequest($request);
            if($form->isSubmitted() && $form->isValid()){
                //Supprimer le token
                $user->setResetToken('');
                $user->setPassword(
                    $passwordHasher->hashPassword(
                        $user,
                        $form->get('password')->getData()
                    )
                );
                $entityManager->persist($user);
                $entityManager->flush();

                $this->addFlash('success', 'Mot de passe réinitialisé avec succés');
                return $this->redirectToRoute('app_login');
            }

            return $this->render('security/reset_password.html.twig',[
                'passForm' => $form->createView()
            ]);
        }
        $this->addFlash('danger', 'Token invalide');
        return $this->redirectToRoute('app_login');
    }
}
