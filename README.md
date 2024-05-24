# secu_projet
projet sécurité présenté par l'équipe N°6 bonne lecture ;)

LE CONTENUE DU CODE:

MENU:
     ATTAQUE : Dans ce code 6 attaques sont implémentées l'attaque par dictionnaire, brute force, par rainbow table , par lookup table,Hybride et dictionnaire amélioré.
     CONSEIL : Pour un mot de passe sécurisé
     TESTER MOT DE PASSE : Cette option donne des conseils personnalisés a l'utilisateur pour ameliorer son mot de passe ,elle est d'auter aussi d'une option qui prédit le temps nécaissaire pour le qu'elle votre 
     mot de passe serra trouvé 
     CONVERTISEUR : Donne le hachage d'un mot de passe entré(en sachant que les mot de passe sont stocké sous cette forme)

Deux fonctions de hachages sont utilisées de la bibliothèque Python hashlib (MD5, SHA1,SHA256),En plus de la bibliothéque passlib qui comporte la forme crypté des 3 méthodes de hachage sité (Kali linux utilise cette forme de hachage ) pour chacune des attaques.

LA FONCTION DE CHAQUE ATTAQUE:

   dictionnaire : crack_password()
                  le fichier : liste.txt de 1987407 mots

   brute force : trouver_bon_mot()
                 jusqu'à 12 caractères 
                 solution pour la rapidité: les threads (max 24 threads modulable a partir de la capacité de chaque pc).

   arc-en-ciel : find_password()
                 fichier : hash_table.txt 'pour MD5' hash_table_sha1.txt 'pour sha1' hash_table_sha256.
                 code de création de la table : testtes.py
                 les deux tables créées  à partir du dictionnaire liste.txt 
                 problemme de temps, solution : threads

   lookup-table : run_lookup_table()
                  fichier : password_dict.pkl 'pour MD5' password_dict_sha1.pkl 'pour SHA1'
                  code de création de la table : dictofile.py

LA VERIFICATION DES HACHAGES:
   le choix de la fonction de hachage est géré avec la variable : dernier_bouton_clique qui nous indique quelle fonction a été choisie 
   et la vérification du hachage entré par l'utilisateur va etre effectuée avec les fonctions message_box_...

SELAGE:
   ajouté un Checkbutton aux deux attaques dictionnaire et rainbow
   Checkbutton géré avec la variable var1 'pour dictionnaire' et var2 'pour brute force'

   SI Checkbutton alors 
       HACHAGE utilisé MD5_CRYPT ou SHA1_CRYPT SHA256_CRYPT avec un round de 1000 de la bibliothèque passlib selon la fonction choisie
       SALT = salt valide 
   SINON HACHAGE base 16 cad implémentés auparavant 

   FONCTION:
   dictionnaire : salt()
   brute force : salt2() -> retrouver_mot()

   ->Lors de l'utilisation du salt comme sur Linux ou les documents office le hachage n'est pas stocké en hexa 
   il est crypté pour cela on a utilisé la lib passlib qui a la meme syntaxe de hachage que linux 

L'INTERFACE GRAPHIQUE:
   Les interfaces graphiques sont gérées à l'aide de la bibliothèque Tkinter

   FENETRE : root
   INTRODUCTION: une video d'into a la platforme "logo1.mp4" dans une autre fenetre root2
   MENU : main_frame dans la quel il ya les boutons de chaque point mentionné dans le menu si-dessus 
         ATTAQUE (attack_button) => choix_fct_frame pour choisir entre MD5 (md5_fct_button) et SHA1 (sha1_fct_button)
                                 => attack_buttons_frame qui comporte les quatres boutons d'attaques (attack_dictionary_button,brute_force_button,rainbow_attack_button,lookup_table_button) 
                                 => chaque attaque a ses propres composants d'interface textfiel,bouton d'attaque,...
                                    et chacune a une fonction qui gére son interface :
                                          dictionnaire : show_dictionary_attack
                                          brute_force_button : show_brute_force_interface
                                          rainbow : show_rainbow_attack_interface
                                          lookup : show_lookup_table
                                 => pour afficher le resultat de l'attaque une frame est utilisé (result_frame)

PS:
la version finale du code se trouve dans le fichier : versionfinalePSW.py
