import hashlib

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction pour réduire un hachage à une chaîne de longueur fixe
def reduction(hachage, longueur=8):
    return hachage[:longueur]

# Fonction pour trouver le mot de passe à partir d'un hachage donné en utilisant la table arc-en-ciel
def trouver_mot_de_passe(hachage_cible, table_arc_en_ciel, longueur_reduction):
    for hachage_reduit, (mot_initial, hachage_initial) in table_arc_en_ciel.items():
        if hachage_cible == hachage_reduit:
            chaine = mot_initial
            while md5(chaine) != hachage_cible:
                chaine = md5(chaine)
            return mot_initial
    return None

# Charger la table arc-en-ciel depuis un fichier
def charger_table_arc_en_ciel(nom_fichier):
    table_arc_en_ciel = {}
    with open(nom_fichier, 'r') as file:
        for line in file:
            hachage_reduit, mot_initial, hachage_initial = line.strip().split()
            table_arc_en_ciel[hachage_reduit] = (mot_initial, hachage_initial)
    return table_arc_en_ciel

# Exemple d'utilisation
if __name__ == "__main__":
    # Charger la table arc-en-ciel depuis un fichier
    nom_fichier_table_arc_en_ciel = "table_arc_en_ciel.txt"
    table_arc_en_ciel = charger_table_arc_en_ciel(nom_fichier_table_arc_en_ciel)
    longueur_reduction=8
    # Hachage cible à craquer
    hachage_cible = input("Entrez le hachage cible à craquer : ")

    # Essayer de retrouver le mot de passe correspondant
    mot_de_passe = trouver_mot_de_passe(hachage_cible, table_arc_en_ciel, longueur_reduction)

    # Afficher le résultat
    if mot_de_passe:
        print(f"Le mot de passe correspondant au hachage {hachage_cible} est: {mot_de_passe}")
    else:
        print("Impossible de trouver le mot de passe.")
