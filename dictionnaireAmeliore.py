import hashlib

def generate_hash(password):
    """Génère un hash SHA-256 pour un mot de passe donné."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_password_list(filename):
    """Charge la liste des mots de passe depuis un fichier."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file]

def apply_transformations(base_password):
    """Applique différentes transformations sur un mot de passe de base."""
    # Vous pouvez ajouter autant de transformations que vous le souhaitez
    transformations = [
        base_password.upper(),
        base_password.lower(),
        base_password.capitalize(),
        base_password + "123",
        base_password + "!",
        "123" + base_password,
        "!"+ base_password,
    ]
    return transformations

def dictionary_attack(hash_target, filename):
    """Effectue une attaque par dictionnaire améliorée."""
    password_list = load_password_list(filename)
    for base_password in password_list:
        if generate_hash(base_password) == hash_target:
                print(f"Mot de passe trouvé : {base_password}")
                return base_password
            
    for base_password in password_list:
        transformations = apply_transformations(base_password)
        for password in transformations:
            if generate_hash(password) == hash_target:
                print(f"Mot de passe trouvé : {password}")
                return password
    print("Aucun mot de passe correspondant trouvé.")
    return None

# Exemple d'utilisation
hash_target = generate_hash("hamad123456")  # Simuler un hash cible
filename = 'liste.txt'  # Nom du fichier contenant les mots de passe potentiels

found_password = dictionary_attack(hash_target, filename)