import olefile
import hashlib


from docx import Document
import hashlib

def crack_password(docx_file, dictionary_file):
    # Ouvrir le document .docx
    doc = Document(docx_file)
    
    # Lire le contenu textuel du document
    content = ""
    for paragraph in doc.paragraphs:
        content += paragraph.text
    
    # Charger les mots du dictionnaire depuis le fichier
    with open(dictionary_file, "r") as file:
        words = [line.strip() for line in file]
    
    # Pour chaque mot dans le dictionnaire
    for word in words:
        # Calculer le hachage du mot
        hashed_word = hashlib.sha256(word.encode()).hexdigest()
        
        # Vérifier si le hachage du mot correspond au contenu du document
        if hashed_word in content:
            print(f"Mot de passe trouvé : {word}")
            return word
    
    print("Aucun mot de passe trouvé.")
    return None

# Utilisation de la fonction crack_password
docx_file = "C:/Users/HP/Desktop/security/secu_projet/Test_security.docx"
dictionary_file = "liste.txt"
crack_password(docx_file, dictionary_file)
'''
def extract_password_hash(docx_file):
    with olefile.OleFileIO(docx_file) as ole:
        for stream_name in ole.listdir():
            if isinstance(stream_name, str) and stream_name.startswith('EncryptionData'):
                stream = ole.openstream(stream_name)
                encryption_data = stream.read()
                stream.close()
                # Supposons que le hachage du mot de passe est stocké dans les 20 premiers octets de la zone de chiffrement
                password_hash = encryption_data[:20]
                return password_hash

# Remplacez "votre_document.docx" par le chemin vers votre document Word verrouillé
docx_file = "Test_security.docx"
password_hash = extract_password_hash(docx_file)

if password_hash:
    print("Hachage du mot de passe extrait :", password_hash.hex())
else:
    print("Aucun hachage de mot de passe n'a été extrait.")
'''