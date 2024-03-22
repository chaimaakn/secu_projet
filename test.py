import hashlib

file_name = "liste.txt"
#exmple de hachage on metre se que on veut pour que le prof verifie 
#original_md5 = input("Entrez le mot de passe haché (MD5): ")
original_md5 = 'ec0e2603172c73a8b644bb9456c1ff6e'  # batman

with open(file_name, 'r') as file_to_check:
    # lire le contenu du fichier ligne par ligne
    for line in file_to_check:
        # supprimer les espaces et les sauts de ligne
        word = line.strip()
        
        # calculer le hash MD5 du mot
        md5_returned = hashlib.md5(word.encode()).hexdigest()
        
        # vérifier si le hash correspond
        if original_md5 == md5_returned:
            print(f"Le mot de passe est {word}")
            break
    else:
        print("Mot de passe non trouvé change de dictionnaire ")