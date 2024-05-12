import hashlib
import itertools
import string
import threading

password_found = False
password_lock = threading.Lock()
le_bon_MotDePasse = None

def crack_password(password_hash):
    characters = string.ascii_letters + string.digits + string.punctuation
    
    for length in range(1, 13):  # Longueur maximale du mot de passe : 12 caractères
        for combination in itertools.product(characters, repeat=length):
            password = ''.join(combination)
            password_bytes = password.encode('utf-8')
            password_md5 = hashlib.md5(password_bytes).hexdigest()
            
            if password_md5 == password_hash:
                return password
    
    return None

def thread_function(password_hash, lengths):
    global password_found
    global le_bon_MotDePasse
    
    characters = string.ascii_letters + string.digits + string.punctuation
    
    for length in lengths:
        for combination in itertools.product(characters, repeat=length):
            with password_lock:
                if password_found:
                    return
            
            password = ''.join(combination)
            password_bytes = password.encode('utf-8')
            password_md5 = hashlib.md5(password_bytes).hexdigest()
            
            if password_md5 == password_hash:
                with password_lock:
                    password_found = True
                    le_bon_MotDePasse = password
                return

def main():
    global le_bon_MotDePasse
    
    password_hash = input("Entrez le hash MD5 du mot de passe à cracker : ")
    
    num_threads = 8  # Nombre de threads à utiliser
    thread_ranges = [(1, 2, 3, 4), (5, 6), (7,), (8,), (9,), (10,), (11,), (12,)]  # Plages de longueur pour chaque thread
    
    threads = []
    for lengths in thread_ranges:
        thread = threading.Thread(target=thread_function, args=(password_hash, lengths))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    if password_found:
        print("Mot de passe trouvé !")
        print("Le bon mot de passe est :", le_bon_MotDePasse)
    else:
        print("Mot de passe non trouvé.")

if __name__ == '__main__':
    main()