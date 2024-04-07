def chercher_mot_dans_fichier(mot, nom_fichier):
    try:
        with open(nom_fichier, 'r') as fichier:
            lignes = fichier.readlines()
            for index, ligne in enumerate(lignes, 1):
                if mot.lower() in ligne.lower():
                    print(f"Le mot '{mot}' a été trouvé dans la ligne {index}: {ligne.strip()}")
                    return  # Quitte la fonction après avoir trouvé la première occurrence
            print(f"Le mot '{mot}' n'a pas été trouvé dans le fichier.")
    except FileNotFoundError:
        print(f"Le fichier '{nom_fichier}' n'a pas été trouvé.")

# Exemple d'utilisation :
mot_a_chercher = input("Entrez le mot que vous voulez chercher dans le fichier : ")
nom_fichier = "liste.txt"  # Nom du fichier où se trouvent les mots
chercher_mot_dans_fichier(mot_a_chercher, nom_fichier)
