import tkinter as tk
from tkinter import ttk, messagebox, font
import cv2
from tqdm import tqdm
from tkmacosx import Button
import hashlib
import time
from datetime import datetime
import string
import itertools
import sys 
import pickle
import pyperclip
from PIL import Image, ImageTk
from passlib.hash import md5_crypt
from passlib.hash import sha1_crypt
import re
import threading
# Couleurs
BG_COLOR = "#000000"
FG_COLOR = "#00ff00"
ACCENT_COLOR = "#ff0000"
PROGRESS_COLOR = "#00ff00"
BUTTON_COLOR = "#000000"  # Couleur des boutons
BUTTON_ACTIVE_COLOR = "#004400"  # Couleur des boutons lorsqu'ils sont actifs

# Police de caractères
FONT_FAMILY = "Courier"
FONT_SIZE = 14

# Frame actuellement affichée
current_frame = None

# Initialiser une variable globale pour stocker le dernier bouton cliqué
dernier_bouton_clique = None

# Fonction appelée lors du clic sur le bouton 1
def bouton1_clique(event):
    global dernier_bouton_clique
    dernier_bouton_clique = 1
    # Instructions spécifiques pour le bouton 1

# Fonction appelée lors du clic sur le bouton 2
def bouton2_clique(event):
    global dernier_bouton_clique
    dernier_bouton_clique = 2
    # Instructions spécifiques pour le bouton 2

# Fonction pour faire clignoter les points
def blink_dots(label, delay=500):
    def show_dots(dots):
        label.config(text="Patienter" + dots)
        label.after(delay, show_dots, dots[1:] + dots[:1])

    show_dots("...")

def handle_shortcuts(event):
    if event.keysym == 'c' and event.state == 4:  # Ctrl+C
        event.widget.event_generate("<<Copy>>")
    elif event.keysym == 'v' and event.state == 4:  # Ctrl+V
        event.widget.event_generate("<<Paste>>")
    elif event.keysym == 'a' and event.state == 4:  # Ctrl+A
        event.widget.event_generate("<<SelectAll>>")

CARACTERES = string.ascii_letters + string.digits + string.punctuation

# Fonction pour calculer le hachage SHA1 d'un mot
def sha1(mot):
    return hashlib.sha1(mot.encode()).hexdigest()

# Fonction pour permettre à l'utilisateur d'entrer un hash et récupérer le mot correspondant
def message_box_sha1(hashed_password):
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return True
    if len(hashed_password) != 40 or not all(c in string.hexdigits for c in hashed_password):
        print("Le hash entré n'est pas valide.")
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return True
    return False

def message_box_md5(hashed_password):
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return True
    if len(hashed_password) != 32 or not all(c in string.hexdigits for c in hashed_password):
        print("Le hash entré n'est pas valide.")
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return True
    return False

def message_box_md5_crypt(hashed_password):
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide de MD5_CRYPT.", parent=root)
        return True
    if len(hashed_password) != 22 or not all(c in string.ascii_letters + string.digits + './' for c in hashed_password):
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide de MD5_CRYPT.", parent=root)
        return True
    return False

#a verifier 
def message_box_sha1_crypt(hashed_password):
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide de SHA1_CRYPT.", parent=root)
        return True
    if len(hashed_password) != 28 or not all(c in string.ascii_letters + string.digits + './' for c in hashed_password):
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide de SHA1_CRYPT.", parent=root)
        return True
    return False

def valid_salt(salt):
    # Expression régulière pour vérifier le format du sel
    pattern = r'^[0-9a-zA-Z./]{1,8}$'
    return bool(re.match(pattern, salt))

def messagebox_salt(salt):
    if not valid_salt(salt):
        messagebox.showerror("Erreur", "Le sel doit contenir jusqu'à 8 caractères alphanumériques, '.' ou '/'.", parent=root)
        return True
    return False


# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction pour tester si un mot correspond au hachage
def est_bon_mot(mot, hash_a_trouver):
    global dernier_bouton_clique
    salt_hash=entry_salt2.get().strip()
    if var2.get()==1:
        if dernier_bouton_clique==1:
            return md5_crypt.using(salt=salt_hash,rounds=1).hash(mot) == hash_a_trouver
        else:
            return sha1_crypt.using(salt=salt_hash,rounds=1).hash(mot) == hash_a_trouver
    else:
        if dernier_bouton_clique==1:
            return md5(mot) == hash_a_trouver
        else:
            return sha1(mot) == hash_a_trouver
    
password_found = False
password_lock = threading.Lock() 
le_bon_MotDePasse = None  
'''def crack_password(password_hash):
    
    
    for length in range(1, 13):  # Longueur maximale du mot de passe : 12 caractères
        for combination in itertools.product(CARACTERES, repeat=length):
            password = ''.join(combination)
            password_bytes = password.encode('utf-8')
            password_md5 = hashlib.md5(password_bytes).hexdigest()
            
            if password_md5 == password_hash:
                return password
    
    return None'''
# Fonction pour trouver le bon mot
def trouver_bon_mot(hash_a_trouver, lengths):
        global password_found
        global le_bon_MotDePasse
        for length in lengths:
         for combination in itertools.product(CARACTERES, repeat=length):
            with password_lock:
                if password_found:
                    return
            
            password = ''.join(combination)
            password_bytes = password.encode('utf-8')
            if dernier_bouton_clique==1:
                 password_md5 = hashlib.md5(password_bytes).hexdigest()
                 if password_md5 == hash_a_trouver:
                   with password_lock:
                    password_found = True
                    le_bon_MotDePasse = password
                    
                   return 
                 
            else:
                password_sha1 = hashlib.sha1(password_bytes).hexdigest()
                if password_sha1 == hash_a_trouver:
                 with password_lock:
                    password_found = True
                    le_bon_MotDePasse = password
                    
                    return 

            
            

    
# Fonction pour permettre à l'utilisateur d'entrer un hash et récupérer le mot correspondant
def retrouver_mot():
    global dernier_bouton_clique
    hash_input=entry_brut_force.get().strip()
    if var2.get()==1:
        salt_hash=entry_salt2.get().strip()
        if messagebox_salt(salt_hash)== True:
            return
        if dernier_bouton_clique==1:
            if message_box_md5_crypt(hash_input)==True:
               return
            hash_input="$1$"+salt_hash+"$"+hash_input
        else:
            if message_box_sha1_crypt(hash_input)==True:
               return
            hash_input="$sha1$1$"+salt_hash+"$"+hash_input
    else:
        if dernier_bouton_clique==1:
            if message_box_md5(hash_input)==True:
                return
        else:
             if message_box_sha1(hash_input)==True:
                return
    num_threads = 8  # Nombre de threads à utiliser
    thread_ranges = [(1, 2, 3, 4), (5, 6), (7,), (8,), (9,), (10,), (11,), (12,)]  # Plages de longueur pour chaque thread
    
    threads = []
    for lengths in thread_ranges:
           thread = threading.Thread(target=trouver_bon_mot, args=(hash_input, lengths))
           threads.append(thread)
           thread.start()
    
    for thread in threads:
           thread.join()   
    
 
    if password_found:
        
        retry_button_brute_force.pack(side=tk.LEFT, padx=10)
        result_label_brute_force.config(text=f"Le mot est: {le_bon_MotDePasse} ", fg=FG_COLOR)
        toggle_back_button(False)

        
    else:
        messagebox.showinfo("Information", "Aucun mot n'a été trouvé.")
    

def show_brute_force_interface():
    global entry_brut_force 
    global current_frame
    global start_brute_force_button,c2
    # Cacher toutes les autres frames
    hide_all_frames()

    # Afficher l'interface pour l'attaque par force brute
    
    label_brute_force.place(relx=0.5, rely=0.3, anchor='center')
    entry_brut_force.place(relx=0.5, rely=0.4, anchor='center')
    start_brute_force_button.place(relx=0.5, rely=0.6, anchor='center') 
    result_frame_brute_force.place(relx=0.5, rely=0.9, anchor='center')
    result_label_brute_force.pack(pady=10)
    password_label_brute_force.pack(side="top", padx=10, pady=5)
    retry_button_brute_force.pack(pady=15)
    retry_button_brute_force.pack_forget()
    brute_force_title.place(relx=0.5, rely=0.1, anchor="center")
    c2= tk.Checkbutton(main_frame, text='Salt',variable=var2, onvalue=1, offvalue=0,selectcolor=ACCENT_COLOR, command=check_salt2,fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
    #c1.place(relx=0.5, rely=0.6, anchor='center')
    c2.pack(expand=1,pady=10)
    current_frame = result_frame_brute_force
    toggle_back_button(True)
    


# Variable pour stocker la valeur actuelle de la barre de progression
current_progress = 0

# Fonction pour afficher/cacher le bouton "Retour"
def toggle_back_button(show):
    if show:
        back_button.place(relx=0, rely=1.0, anchor='sw')
    else:
        back_button.place_forget()
        

# Fonction pour cacher toutes les frames

def hide_all_frames():
    attack_buttons_frame.place_forget()
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()
    progress_bar.place_forget()
    percentage_label.place_forget()
    blink_label.place_forget()
    result_frame.place_forget()
    result_frame_brute_force.place_forget()
    result_label_brute_force.place_forget()
    password_label_brute_force.place_forget
    entry_brut_force.delete(0, tk.END)
    result_frame_lookup_table.place_forget()
    result_label_lookup_table.place_forget()
    password_label_lookup_table.place_forget()
    label_lookup_table.place_forget()
    entry_lookup_table.place_forget()
    result_frame_rainbow.place_forget()
    result_label_rainbow.config(text="")
    password_label_rainbow.config(text="")
    retry_button_rainbow.pack_forget() 
    button_frame.place_forget()   
    entry_rainbow.delete(0, tk.END)
    label_rainbow.place_forget() 
    choix_fct_frame.place_forget()
    convertisseur_frame.place_forget()
    md5_frame.place_forget()
    sha1_frame.place_forget()
    salt_label.place_forget()
    entry_salt.place_forget()
    bouton_salt.place_forget()
    c1.destroy()
    salt_label2.place_forget()
    entry_salt2.place_forget()
    bouton_salt2.place_forget()
    c2.destroy()

# Fonction pour cacher la frame de saisie du mot de passe haché
def hide_password_entry():
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()

# Fonction pour réinitialiser la barre de progression
def reset_progress_bar():
    global current_progress
    current_progress = 0
    progress_bar.config(value=current_progress)  # Réinitialiser la valeur de la barre de progression
    percentage_label.config(text=f"{current_progress}%")  # Réinitialiser le label de pourcentage

# Fonction pour afficher l'interface de l'attaque par dictionnaire
def show_dictionary_attack():
    global current_frame,c1
    hide_all_frames()  # Cacher toutes les frames

    # Afficher l'interface de l'attaque par dictionnaire
    label_hashed_password.place(relx=0.5, rely=0.30, anchor='center')
    entry_hashed_password.place(relx=0.5, rely=0.4, anchor='center')
    dic_title.place(relx=0.5, rely=0.1, anchor="center")
    crack_button.place(relx=0.5, rely=0.6, anchor='center')
    c1 = tk.Checkbutton(main_frame, text='Salt',variable=var1, onvalue=1, offvalue=0,selectcolor=ACCENT_COLOR, command=check_salt,fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
    #c1.place(relx=0.5, rely=0.6, anchor='center')
    c1.pack(expand=1,pady=10)
    current_frame = label_hashed_password
    toggle_back_button(True)

# Fonction pour retourner à l'écran précédent
def return_to_previous_screen():
    global current_frame,c1,c2
    if current_frame == result_frame:
        result_frame.place_forget()
        show_dictionary_attack()
    elif current_frame == progress_bar:
        reset_progress_bar()
        progress_bar.place_forget()
        percentage_label.place_forget()
        blink_label.place_forget()
        result_label.place_forget()
        password_label.place_forget()
        show_dictionary_attack()
    elif current_frame == result_frame_brute_force:
        back_button.place_forget()
        result_frame_brute_force.place_forget()
        result_label_brute_force.place_forget()
        password_label_brute_force.place_forget
        entry_brut_force.place_forget()
        label_brute_force.place_forget()
        start_brute_force_button.place_forget()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        brute_force_title.place_forget()
        salt_label2.place_forget()
        entry_salt2.place_forget()
        bouton_salt2.place_forget()
        var2.set(0) 
        c2.place_forget()
        c2.destroy()
        current_frame = attack_buttons_frame
        toggle_back_button(True)
    elif current_frame == result_frame_lookup_table:
        back_button.place_forget()
        result_frame_lookup_table.place_forget()
        result_label_lookup_table.place_forget()
        password_label_lookup_table.place_forget
        entry_lookup_table.place_forget()
        label_lookup_table.place_forget()
        start_lookup_table_button.place_forget()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        lookup_table_title.place_forget()
        current_frame = attack_buttons_frame
        toggle_back_button(True)   
    elif current_frame == result_frame_rainbow:
        hide_password_entry()  
        result_frame_rainbow.place_forget() 
        entry_rainbow.place_forget()
        label_rainbow.place_forget()
        crack_rainbow_button.place_forget()
        rainbow_title.place_forget()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = attack_buttons_frame
        toggle_back_button(True)   
    elif current_frame in (label_hashed_password, entry_hashed_password, crack_button):
        hide_password_entry()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        dic_title.place_forget()
        salt_label.place_forget()
        entry_salt.place_forget()
        bouton_salt.place_forget()
        var1.set(0) 
        c1.place_forget()
        c1.destroy()
        current_frame = attack_buttons_frame
        toggle_back_button(True)  # Cacher le bouton "Retour"
    elif current_frame==result_frame_test_password:
        label_test_password.place_forget()
        entry_test_password.place_forget()
        test_password_button.place_forget()
        result_frame_test_password.place_forget()
        result_label_test_password.place_forget()
        reset_button_test_password.place_forget()
        button_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = button_frame
        toggle_back_button(False)   
    elif current_frame== advice_frame:
        advice_frame.place_forget()
        button_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = button_frame
        toggle_back_button(False)  
    elif current_frame== attack_buttons_frame:
        attack_buttons_frame.place_forget()
        choix_fct_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = choix_fct_frame
        toggle_back_button(True) 
    elif current_frame==choix_fct_frame:
        choix_fct_frame.place_forget()
        button_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = button_frame
        toggle_back_button(False) 
    elif current_frame==convertisseur_frame:
        convertisseur_frame.place_forget()
        button_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = button_frame
        toggle_back_button(False) 
    elif current_frame==md5_frame:
        md5_frame.place_forget()
        convertisseur_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = convertisseur_frame
        toggle_back_button(True) 
    elif current_frame==sha1_frame:
        sha1_frame.place_forget()
        convertisseur_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = convertisseur_frame
        toggle_back_button(True) 
    elif current_frame == button_frame:
        pass

   
# Fonction pour cracker le mot de passe
def crack_password():
    global current_frame, current_progress, dernier_bouton_clique,c1
    hashed_password = entry_hashed_password.get().strip()
    
    if dernier_bouton_clique==1:
        if message_box_md5(hashed_password)==True:
            return
    else:
        if message_box_sha1(hashed_password)==True:
            return
    
    hide_all_frames()
    # Cacher tous les widgets sauf la barre de progression et le label clignotant
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()
    result_frame.place_forget()

    with open("liste.txt", "r") as file:
        words = [line.strip() for line in file]

    progress_bar.config(maximum=100)
    progress_bar.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    percentage_label.place(relx=0.5, rely=0.28, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    blink_label.place(relx=0.5, rely=0.45, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas
    blink_dots(blink_label)  # Démarrer le clignotement des points
    current_frame = progress_bar
    c1.destroy()
    toggle_back_button(True)


    for progress in tqdm(range(101), desc="Chercher...", unit="%", leave=False):
        current_progress = progress
        progress_bar.config(value=current_progress)
        percentage_label.config(text=f"{current_progress}%")
        root.update()
        time.sleep(0.05)

    reset_progress_bar()  # Réinitialiser la barre de progression après la boucle

    progress_bar.place_forget()  # Cacher la barre de progression
    percentage_label.place_forget()  # Cacher le label de pourcentage
    blink_label.place_forget()  # Cacher le label clignotant

    if current_frame == progress_bar:
        if dernier_bouton_clique == 1:
            for word in words:
                md5_hash = hashlib.md5(word.encode()).hexdigest()
                if hashed_password == md5_hash:
                    result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
                    password_label.config(text=word, fg=ACCENT_COLOR)
                    result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
                    current_frame = result_frame
                    toggle_back_button(False)
                    return
        else:
            for word in words:
                sha1_hash = hashlib.sha1(word.encode()).hexdigest()
                if hashed_password == sha1_hash:
                    result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
                    password_label.config(text=word, fg=ACCENT_COLOR)
                    result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
                    current_frame = result_frame
                    toggle_back_button(False)
                    return


        result_label.config(text="Tentative échouée", fg=ACCENT_COLOR)
        password_label.config(text="")
        result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
        current_frame = result_frame
        toggle_back_button(False)
    
#fonction pour l'attaque lookup table 
def run_lookup_table():
    global current_frame, current_progress,dernier_bouton_clique
    hashed_password = entry_lookup_table.get().strip()

    if dernier_bouton_clique==1:
        if message_box_md5(hashed_password)==True:
            return
    else:
        if message_box_sha1(hashed_password)==True:
            return
        
    hide_all_frames()
    if dernier_bouton_clique==1:
        with open("password_dict.pkl", "rb") as file:
         password_dic = pickle.load(file)
    else:
        with open("password_dict_sha1.pkl", "rb") as file:
         password_dic = pickle.load(file)

    if hashed_password in password_dic:
        result_label_lookup_table.config(text=f"Le mot de passe est :", fg=FG_COLOR)
        password_label_lookup_table.config(text=password_dic[hashed_password], fg=ACCENT_COLOR)
        result_frame_lookup_table.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
        retry_button_lookup_table.pack(side=tk.LEFT, padx=10)
        current_frame = result_frame_lookup_table
        toggle_back_button(False)
        
    else:
        result_label_lookup_table.config(text="Tentative échouée", fg=ACCENT_COLOR)
        password_label_lookup_table.config(text="")
        result_frame_lookup_table.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
        retry_button_lookup_table.pack(side=tk.LEFT, padx=10)
        current_frame = result_frame_lookup_table
        toggle_back_button(False)   


# Fonction pour afficher l'interface de l'attaque par lookup table
def show_lookup_table():
    global entry_lookup_table 
    global current_frame
    global start_lookup_table_button
    # Cacher toutes les autres frames
    hide_all_frames()

    # Afficher l'interface pour l'attaque par lookup table
    
    label_lookup_table.place(relx=0.5, rely=0.3, anchor='center')
    entry_lookup_table.place(relx=0.5, rely=0.4, anchor='center')
    start_lookup_table_button.place(relx=0.5, rely=0.5, anchor='center') 
    result_frame_lookup_table.place(relx=0.5, rely=0.6, anchor='center')
    result_label_lookup_table.pack(pady=5)
    password_label_lookup_table.pack(pady=5)
    retry_button_lookup_table.place(relx=0.5, rely=0.10, anchor='center')
    retry_button_lookup_table.pack(pady=15)
    retry_button_lookup_table.pack_forget()
    lookup_table_title.place(relx=0.5, rely=0.1, anchor="center")
    
    current_frame = result_frame_lookup_table
    toggle_back_button(True)

# Fonction de réduction
def reduction_md5(hash_value):
    hash_obj = hashlib.md5(hash_value.encode())
    return hash_obj.hexdigest()

def reduction_sha1(hash_value):
    hash_obj = hashlib.sha1(hash_value.encode())
    return hash_obj.hexdigest()

# Fonction pour retrouver le mot de passe à partir d'un hachage MD5
def find_password(target_hash):
    global dernier_bouton_clique
    j=0
    # Vérifier si le hachage cible correspond à un hachage initial
    if target_hash in rainbow_table:
        return rainbow_table[target_hash][0]

    # Parcourir les chaînes de la table arc-en-ciel
    for start_hash, (password, end_hash) in rainbow_table.items():
        chain = [start_hash]
        current_hash = start_hash
        for _ in range(1000):
            if dernier_bouton_clique==1:
               current_hash = reduction_md5(current_hash)
            else:
                current_hash = reduction_sha1(current_hash)
            chain.append(current_hash)
            if current_hash == target_hash:
                # Reconstruire le mot de passe à partir de la chaîne
                candidate=start_hash
                if dernier_bouton_clique==1:
                   for i in range(len(chain)-1):
                       password=candidate
                       candidate = hashlib.md5(chain[i].encode()).hexdigest()
                else: 
                    for i in range(len(chain)-1):
                       password=candidate
                       candidate = hashlib.md5(chain[i].encode()).hexdigest()
                return password  
                         
    # Hachage non trouvé dans la table
    return None

rainbow_table = {}

# Fonction pour effectuer une attaque Rainbow
def run_rainbow(entry_rainbow):
    target_hash = entry_rainbow.get().strip()

    # Charger la table arc-en-ciel depuis le fichier

    if dernier_bouton_clique==1:
        with open('hash_table.txt', 'r') as file:
            for line in file:
                start_hash, entry = line.strip().split(': ')
                password, end_hash = entry.split(' -> ')
                rainbow_table[start_hash] = (password, end_hash)
    else:
        with open('hash_table_sha1.txt', 'r') as file:
            for line in file:
                start_hash, entry = line.strip().split(': ')
                password, end_hash = entry.split(' -> ')
                rainbow_table[start_hash] = (password, end_hash)

    # Vérifier si le hachage cible est dans la table
    password = find_password(target_hash)

    return password

# Fonction pour afficher l'interface de l'attaque Rainbow
def show_rainbow_attack_interface():
    global current_frame
    global entry_rainbow
    hide_all_frames()  # Cacher toutes les frames sauf celle de l'attaque Rainbow
    
    # Affichage de l'interface
    label_rainbow.place(relx=0.5, rely=0.3, anchor='center')
    entry_rainbow.place(relx=0.5, rely=0.4, anchor='center')
    crack_rainbow_button.place(relx=0.5, rely=0.5, anchor='center')
    result_frame_rainbow.place(relx=0.5, rely=0.6, anchor='center')
    result_label_rainbow.pack(pady=5)  
    password_label_rainbow.pack(pady=5) 
    retry_button_rainbow.place(relx=0.5, rely=0.10, anchor='center')
    retry_button_rainbow.pack(pady=15)
    retry_button_rainbow.pack_forget() 
    back_button.place(relx=0, rely=1.0, anchor='sw') 
    rainbow_title.place(relx=0.5, rely=0.1, anchor="center")
    current_frame = result_frame_rainbow  
    toggle_back_button(True)
    
# Fonction pour lancer l'attaque Rainbow

def launch_rainbow_attack(entry_hashed_password):
    global current_frame, current_progress
    hashed_password = entry_hashed_password.get().strip()

    if dernier_bouton_clique==1:
        if message_box_md5(hashed_password)==True:
            return
    elif dernier_bouton_clique==2:
        if message_box_sha1(hashed_password)==True:
            return
    
    # Cacher le champ de texte et le bouton "Cracker"
    label_rainbow.place_forget()
    entry_rainbow.place_forget()
    crack_rainbow_button.place_forget()
    
    # Cacher le résultat précédent s'il y en a un
    password_label_rainbow.pack_forget()
    
    # Affichage de la barre de progression et des autres éléments associés
    progress_bar.place(relx=0.5, rely=0.35, anchor='center')
    progress_bar.config(maximum=100)
    progress_bar.start()
    progress_bar.step(0)
    percentage_label.place(relx=0.5, rely=0.28, anchor='center')
    blink_label.place(relx=0.5, rely=0.45, anchor='center')
    blink_dots(blink_label)
    current_frame = progress_bar
    toggle_back_button(False)
    
    # Boucle de progression
    for progress in tqdm(range(101), desc="Recherche...", unit="%", leave=False):
        current_progress = progress
        progress_bar.config(value=current_progress)
        percentage_label.config(text=f"{current_progress}%")
        root.update()
        time.sleep(0.05)
    
    # Réinitialisation de la barre de progression
    reset_progress_bar()
    
    # Cacher les éléments associés à la barre de progression
    progress_bar.place_forget()
    percentage_label.place_forget()
    blink_label.place_forget()
    toggle_back_button(False)
    
    # Affichage des résultats
    result = run_rainbow(entry_hashed_password)
    if result:
        result_label_rainbow.config(text="Le mot de passe est :", fg=FG_COLOR)
        password_label_rainbow.config(text=result, fg=ACCENT_COLOR)
        result_frame_rainbow.place(relx=0.5, rely=0.5, anchor='center') 
        password_label_rainbow.pack(pady=5) 
        retry_button_rainbow.pack(side=tk.LEFT, padx=10)
        current_frame = result_frame_rainbow
    else:
        result_label_rainbow.config(text="Tentative échouée", fg=ACCENT_COLOR)
        retry_button_rainbow.pack(pady=15)
        
    toggle_back_button(False)
    
def show_password_test_interface():
    global current_frame
    # Cacher toutes les frames
    hide_all_frames()
    # Afficher l'interface de test du mot de passe
    label_test_password.place(relx=0.5, rely=0.3, anchor='center')
    entry_test_password.place(relx=0.5, rely=0.4, anchor='center')
    test_password_button.place(relx=0.5, rely=0.48, anchor='center')
    result_frame_test_password.place(relx=0.5, rely=0.6, anchor='center')
    result_label_test_password.pack(pady=10)
    reset_button_test_password.pack_forget() 
    current_frame = result_frame_test_password
    toggle_back_button(True)

def test_password():
    global current_frame
    password = entry_test_password.get().strip()
    if not password:
        result_label_test_password.config(text="Veuillez entrer un mot de passe.", fg=ACCENT_COLOR)
    else:
        # Vérifier la longueur du mot de passe
        if len(password) < 12:
            result_label_test_password.config(text="Votre mot de passe est trop court.\n Il doit contenir au moins 12 caractères.", fg=ACCENT_COLOR)
        else:
            # Vérifier la présence de majuscules
            if not any(char.isupper() for char in password):
                result_label_test_password.config(text="Votre mot de passe doit contenir \n au moins une majuscule.", fg=ACCENT_COLOR)
            else:
                # Vérifier la présence de caractères spéciaux
                special_chars = string.punctuation
                if not any(char in special_chars for char in password):
                    result_label_test_password.config(text="Votre mot de passe doit contenir \n au moins un caractère spécial.", fg=ACCENT_COLOR)
                else:
                 numero=string.digits
                 if not any(char in numero for char in password):
                    result_label_test_password.config(text="Votre mot de passe doit contenir \n au moins un chiffre.",fg=ACCENT_COLOR)
                 else:
                    hashed_password = md5(password)
                    with open("password_dict.pkl", "rb") as file:
                        password_dict = pickle.load(file)
                    if hashed_password in password_dict:
                        result_label_test_password.config(text="Votre mot de passe est considéré comme faible.", fg=ACCENT_COLOR)
                    else:
                        result_label_test_password.config(text="Votre mot de passe est considéré comme sûr.", fg=FG_COLOR)

    reset_button_test_password.pack(side=tk.LEFT, padx=10)  # Afficher le bouton "Réinitialiser"
    current_frame = result_frame_test_password
    toggle_back_button(True)
def show_advice():
    global current_frame
    
    # Cacher les éléments de la frame précédente
    hide_all_frames()
    # Créer la frame pour les conseils
    advice_frame.place(relx=0.5, rely=0.5, anchor="center", width=500, height=400)
    advice_title.place(relx=0.5, rely=0.1, anchor="center")
    advice_label.place(relx=0.5, rely=0.5, anchor="center")
    toggle_back_button(True)
    current_frame = advice_frame 
      
def show_interface_md5():
    global current_frame
    
    hide_all_frames()
    md5_frame.place(relx=0.5, rely=0.5, anchor="center", width=500, height=400)
    label_md5.place(relx=0.5, rely=0.3, anchor='center')
    entry_md5.place(relx=0.5, rely=0.4, anchor='center')
    md5_search_button.place(relx=0.5, rely=0.48, anchor='center')
    current_frame=md5_frame
    toggle_back_button(True)
   
    
def md5_function():
    global current_frame
    
    password=entry_md5.get().strip()
    label_result_md5.config(text="Hachage md5:\n"+md5(password))
    label_result_md5.place(relx=0.5,rely=0.6,anchor='center')
    pyperclip.copy(md5(password))
    label_copie.place(relx=0.5,rely=0.8,anchor='center')
    current_frame=md5_frame
    toggle_back_button(True)
def show_interface_sha1():
    global current_frame
    
    hide_all_frames()
    sha1_frame.place(relx=0.5, rely=0.5, anchor="center", width=500, height=400)
    label_sha1.place(relx=0.5, rely=0.3, anchor='center')
    entry_sha1.place(relx=0.5, rely=0.4, anchor='center')
    sha1_search_button.place(relx=0.5, rely=0.48, anchor='center')
    current_frame=sha1_frame
    toggle_back_button(True)
    
def sha1_function():
    global current_frame
    
    password=entry_sha1.get().strip()
    label_result_sha1.config(text="Hachage sha1:\n"+sha1(password))
    label_result_sha1.place(relx=0.5,rely=0.6,anchor='center')
    pyperclip.copy(sha1(password))
    label_copie_sha1.place(relx=0.5,rely=0.8,anchor='center')
    current_frame=sha1_frame
    toggle_back_button(True)

# Fonction pour réinitialiser l'interface
def reset_password_test_interface():
    global current_frame
    entry_test_password.delete(0, tk.END)  # Effacer le contenu du champ de saisie
    result_label_test_password.config(text="")  # Réinitialiser le label de résultat
    current_frame = result_frame_test_password
    show_password_test_interface()
    toggle_back_button(True)
def retry():
    global current_frame
    # Cacher les éléments de la tentative précédente
    result_frame.place_forget()
    result_label.config(text="")
    password_label.config(text="")

    # Réinitialiser l'interface de l'attaque par dictionnaire
    show_dictionary_attack()
    
def retrybr():
    global current_frame
    hide_all_frames()
    # Cacher les éléments de la tentative précédente
    result_frame_brute_force.place_forget()
    result_label_brute_force.config(text="")
    password_label_brute_force.config(text="")
    entry_brut_force.delete(0, tk.END)
    var2.set(0)
    # Réinitialiser l'interface de l'attaque par dictionnaire
    show_brute_force_interface()

def retrylookuptable():
    global current_frame
    hide_all_frames()
    # Cacher les éléments de la tentative précédente
    result_frame_lookup_table.place_forget()
    result_label_lookup_table.config(text="")
    password_label_lookup_table.config(text="")
   
    # Réinitialiser l'interface de l'attaque par lookup table
    show_lookup_table()   

def retryrnb():
    global current_frame
    hide_all_frames()
    # Cacher les éléments de la tentative précédente
    result_frame_rainbow.place_forget()
    result_label_rainbow.config(text="")
    password_label_rainbow.config(text="")
    entry_hashed_password.delete(0, tk.END)
    # Réinitialiser l'interface 
    show_rainbow_attack_interface()

# Obtenir la date et l'heure actuelles
def get_current_datetime():
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return date_time

def check_salt():
    if var1.get()==0:
        crack_button.place(relx=0.5, rely=0.6, anchor='center')
        salt_label.place_forget()
        entry_salt.place_forget()
        bouton_salt.place_forget()
    else:
        crack_button.place_forget()
        salt_label.place(relx=0.5, rely=0.6, anchor='center') 
        entry_salt.place(relx=0.5, rely=0.7, anchor='center') 
        bouton_salt.place(relx=0.5, rely=0.8, anchor='center') 
def check_salt2():
    if var2.get()==0:
        start_brute_force_button.place(relx=0.5, rely=0.6, anchor='center')
        salt_label2.place_forget()
        entry_salt2.place_forget()
        bouton_salt2.place_forget()
    else:
        start_brute_force_button.place_forget()
        salt_label2.place(relx=0.5, rely=0.6, anchor='center') 
        entry_salt2.place(relx=0.5, rely=0.7, anchor='center') 
        bouton_salt2.place(relx=0.5, rely=0.8, anchor='center') 
            
        
def salt():
    global current_frame, current_progress, dernier_bouton_clique,c1
    hashed_password = entry_hashed_password.get().strip()
    salt_hash=entry_salt.get().strip()
    
    if messagebox_salt(salt_hash)== True :
       return
    
    if dernier_bouton_clique==1:
        if message_box_md5_crypt(hashed_password)==True:
            return
        chaine_inter = "$1$" + salt_hash + "$"
        hashed_password=chaine_inter+hashed_password
    else:
        if message_box_sha1_crypt(hashed_password)==True:
            return
        hashed_password="$sha1$1$"+salt_hash+"$"+hashed_password
    

    hide_all_frames()
    # Cacher tous les widgets sauf la barre de progression et le label clignotant
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()
    result_frame.place_forget()

    with open("liste.txt", "r") as file:
        words = [line.strip() for line in file]

    progress_bar.config(maximum=100)
    progress_bar.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    percentage_label.place(relx=0.5, rely=0.28, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    blink_label.place(relx=0.5, rely=0.45, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas
    blink_dots(blink_label)  # Démarrer le clignotement des points
    current_frame = progress_bar
    var1.set(0) 
    c1.destroy()
    toggle_back_button(True)


    for progress in tqdm(range(101), desc="Chercher...", unit="%", leave=False):
        current_progress = progress
        progress_bar.config(value=current_progress)
        percentage_label.config(text=f"{current_progress}%")
        root.update()
        time.sleep(0.05)

    reset_progress_bar()  # Réinitialiser la barre de progression après la boucle

    progress_bar.place_forget()  # Cacher la barre de progression
    percentage_label.place_forget()  # Cacher le label de pourcentage
    blink_label.place_forget()  # Cacher le label clignotant
     
    if current_frame == progress_bar:
        if dernier_bouton_clique == 1:
            for word in words:
                md5_hash = md5_crypt.using(salt=salt_hash).hash(word)
                if hashed_password == md5_hash:
                    result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
                    password_label.config(text=word, fg=ACCENT_COLOR)
                    result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
                    current_frame = result_frame
                    toggle_back_button(False)
                    return
        else:
            for word in words:
                sha1_hash = sha1_crypt.using(salt=salt_hash,rounds=1).hash(word)
                if hashed_password == sha1_hash:
                    result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
                    password_label.config(text=word, fg=ACCENT_COLOR)
                    result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
                    current_frame = result_frame
                    toggle_back_button(False)
                    return

        result_label.config(text="Tentative échouée", fg=ACCENT_COLOR)
        password_label.config(text="")
        result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
        current_frame = result_frame
        toggle_back_button(False)
        
        
def salt2():
    retrouver_mot()

    
   
            
# Configuration de la fenêtre principale
window_width=550
window_height=500

'''def update_frame():
    ret, frame = cap.read()
    if ret:
        root.withdraw()
        cv2_img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img_tk = ImageTk.PhotoImage(Image.fromarray(cv2_img))
        canvas.create_image(0, 0, anchor=tk.NW, image=img_tk)
        canvas.img = img_tk
        #intro_window.after(30, update_frame)
    else:
        root.deiconify()
        root2.withdraw()
        cap.release()
        canvas.destroy()
    root2.after(30, update_frame)'''
    
    
root = tk.Tk()
root.title("Attaques sur les mots de passes")
root.configure(bg=BG_COLOR)
root.config(highlightbackground="#00ff00", highlightcolor="#00ff00", highlightthickness=0.5)
#root.geometry('550x500')  # Définir la taille de la fenêtre
# Centre the window relative to the dimensions of the screen 
root.geometry('{0:d}x{1}+{2}+{3}'.format(window_width, window_height, root.winfo_screenwidth() // 2 - window_width // 2, root.winfo_screenheight() // 2 - window_height // 2))
'''cap = cv2.VideoCapture("logo1.mp4")

# Créer une fenêtre Tkinter pour afficher la vidéo
root2 = tk.Toplevel(root)
root2.title("Chargement...")
root2.config(highlightbackground="#00ff00", highlightcolor="#00ff00", highlightthickness=0.5)
#root.geometry('550x500')  # Définir la taille de la fenêtre
# Centre the window relative to the dimensions of the screen 
root2.geometry('{0:d}x{1}+{2}+{3}'.format(window_width, window_height, root2.winfo_screenwidth() // 2 - window_width // 2, root2.winfo_screenheight() // 2 - window_height // 2))
root2.grid_rowconfigure(0, weight=1)
root2.grid_columnconfigure(0, weight=1)
# Créer un canvas pour afficher la vidéo
canvas = tk.Canvas(root2, width=window_width, height=window_height, highlightthickness=0)
canvas.pack()'''
'''
# Obtenir les dimensions de la fenêtre
window_width = root.winfo_reqwidth()
window_height = root.winfo_reqheight()
# Calculer les coordonnées pour centrer la fenêtre
position_right = int(root.winfo_screenwidth()/2 - window_width/2)
position_down = int(root.winfo_screenheight()/2 - window_height/2)
'''
# Définir la position de la fenêtre au milieu de l'écran
#root.geometry("+{}+{}".format(position_right, position_down))

# Ajout d'une marge à côté des bordures
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
main_frame = tk.Frame(root, bg=BG_COLOR)
main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

# Nouvelle frame avant la frame principale
'''''
intro_frame = tk.Frame(root, bg=BG_COLOR)
intro_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
'''
custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Boutons dans la nouvelle frame
button_frame=tk.Frame(main_frame,bg=BG_COLOR)
button_frame.place(relx=0.5,rely=0.5,anchor='center')
attack_button = Button(button_frame, text="Attaque", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda:toggle_frames(button_frame,choix_fct_frame))
#attack_button = Button(button_frame, text="Attaque", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(button_frame,attack_buttons_frame))
advice_button = Button(button_frame, text="Conseil", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR,command=show_advice)
test_password_button = Button(button_frame, text="Tester votre mot de passe", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=show_password_test_interface)
convertisseur = Button(button_frame, text="Convertisseur", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(button_frame,convertisseur_frame))

attack_button.pack(pady=10)
advice_button.pack(pady=10)
test_password_button.pack(pady=10)
convertisseur.pack(pady=10)

# l'interface du choix de la fonction de hachage pour convertisseur
convertisseur_frame = tk.Frame(main_frame, bg=BG_COLOR)

title_label = tk.Label(convertisseur_frame, text="Choisissez une fonction de hachage ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BG_COLOR)
title_label.pack(pady=10)

#md5_button = Button(convertisseur_frame, text=" MD5 ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BUTTON_COLOR, activebackground=BUTTON_ACTIVE_COLOR, command=lambda: toggle_frames(convertisseur_frame,md5_frame))
md5_button = Button(convertisseur_frame, text=" MD5 ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BUTTON_COLOR, activeforeground=ACCENT_COLOR,command=show_interface_md5)
md5_button.pack(pady=10)

sha1_button = Button(convertisseur_frame, text=" SHA1 ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BUTTON_COLOR, activeforeground=ACCENT_COLOR, command=show_interface_sha1)
sha1_button.pack(pady=10)

# l'interface du choix de la fonction de hachage
choix_fct_frame = tk.Frame(root, bg=BG_COLOR)

title_label = tk.Label(choix_fct_frame, text="Choisissez une fonction de hachage ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BG_COLOR)
title_label.pack()

md5_fct_button = Button(choix_fct_frame, text=" MD5 ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BUTTON_COLOR,  activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(choix_fct_frame,attack_buttons_frame))
md5_fct_button.bind("<Button-1>",bouton1_clique)
md5_fct_button.pack(pady=10)

sha1_fct_button = Button(choix_fct_frame, text=" SHA1 ", font=(FONT_FAMILY, FONT_SIZE), fg=FG_COLOR, bg=BUTTON_COLOR,  activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(choix_fct_frame,attack_buttons_frame))
sha1_fct_button.bind("<Button-1>",bouton2_clique)
sha1_fct_button.pack(pady=10)

def toggle_frames(hide_frame, show_frame):
    global current_frame
    
    hide_frame.place_forget()
    show_frame.place(relx=0.5, rely=0.5, anchor='center')
    current_frame=show_frame
    toggle_back_button(True)


# Police personnalisée
custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Frame pour les boutons d'attaque
attack_buttons_frame = tk.Frame(main_frame, bg=BG_COLOR)

# Boutons pour les différentes attaques

attack_dictionary_button = Button(attack_buttons_frame, text="Attaque par dictionnaire", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=show_dictionary_attack)
attack_dictionary_button.pack(pady=10)

brute_force_button = Button(attack_buttons_frame, text="Brute Force", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=show_brute_force_interface)
brute_force_button.pack(pady=10)

rainbow_attack_button = Button(attack_buttons_frame, text="Rainbow Attack", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR,command=show_rainbow_attack_interface)
rainbow_attack_button.pack(pady=10)

lookup_table_button = Button(attack_buttons_frame, text="Lookup Table", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR,command=show_lookup_table)
lookup_table_button.pack(pady=10)


# Label pour le mot de passe haché
label_hashed_password = tk.Label(main_frame, text="Entrez le mot de passe haché :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)

# Entrée pour le mot de passe haché
entry_hashed_password = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)

# Bouton pour cracker le mot de passe
crack_button = Button(main_frame, text="Cracker le mot de passe", command=crack_password, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
var1 = tk.IntVar()
c1 = tk.Checkbutton(main_frame, text='Salt',variable=var1, onvalue=1, offvalue=0,selectcolor=ACCENT_COLOR, command=check_salt,fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
#c1.pack()
#c1.place(relx=0.5, rely=0.6, anchor='center')
#c1.place_forget()
salt_label=tk.Label(main_frame, text="Entrez le salt:", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
entry_salt=tk.Entry(main_frame, width=20, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
bouton_salt= Button(main_frame, text="Cracker le mot de passe", command=salt, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
#root.bind("<Return>", lambda event: crack_button.invoke())
dic_title=tk.Label(main_frame, text="Attaque par dictionnaire", fg=ACCENT_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE, "bold"))
#Declaration brut force 
label_brute_force = tk.Label(main_frame, text="Entrez votre mot de passe haché :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
start_brute_force_button = Button(main_frame, text="Rechercher", command=retrouver_mot, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, width=150)
brute_force_title=tk.Label(main_frame, text="Attaque brute force", fg=ACCENT_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE, "bold"))

# Bouton pour cracker le mot de passe
var2 = tk.IntVar()
c2 = tk.Checkbutton(main_frame, text='Salt',variable=var2, onvalue=1, offvalue=0,selectcolor=ACCENT_COLOR, command=check_salt2,fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
#c1.pack()
#c1.place(relx=0.5, rely=0.6, anchor='center')
#c1.place_forget()
salt_label2=tk.Label(main_frame, text="Entrez le salt:", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
entry_salt2=tk.Entry(main_frame, width=20, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
bouton_salt2= Button(main_frame, text="Rechercher", command=salt2, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
entry_brut_force = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
#root.bind("<Return>", lambda event: start_brute_force_button.invoke())

#Declaration lookup table 
label_lookup_table = tk.Label(main_frame, text="Entrez votre mot de passe haché :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
start_lookup_table_button = Button(main_frame, text="Rechercher", command=run_lookup_table, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, width=150)
lookup_table_title=tk.Label(main_frame, text="Lookup table", fg=ACCENT_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE, "bold"))
entry_lookup_table = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
#root.bind("<Return>", lambda event: start_lookup_table_button.invoke())

#declaration rainbow
label_rainbow = tk.Label(main_frame, text="Entrez votre mot de passe haché :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
entry_rainbow = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
crack_rainbow_button = Button(main_frame, text="Craquer le mot de passe", command=lambda:launch_rainbow_attack(entry_rainbow), fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
#root.bind("<Return>", lambda event: crack_rainbow_button.invoke())

# Barre de progression
progress_bar = ttk.Progressbar(main_frame, length=400, mode="determinate", style="Custom.Horizontal.TProgressbar")

# Label pour afficher le pourcentage
percentage_label = tk.Label(main_frame, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Label clignotant
blink_label = tk.Label(main_frame, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Frame pour afficher le résultat et le bouton "Nouvelle tentative"
result_frame = tk.Frame(main_frame, bg=BG_COLOR)
result_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label.pack(side=tk.LEFT, padx=10)
password_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label.pack(side=tk.LEFT)
retry_button = Button(result_frame, text="Nouvelle tentative", command=retry, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button.pack(side=tk.LEFT, padx=10)

# Frame pour afficher le résultat et le bouton "Nouvelle tentative" pour l'attaque par force brute
result_frame_brute_force = tk.Frame(main_frame, bg=BG_COLOR)
result_label_brute_force = tk.Label(result_frame_brute_force, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label_brute_force.pack(side=tk.LEFT, padx=10)
password_label_brute_force = tk.Label(result_frame_brute_force, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label_brute_force.pack(side=tk.LEFT)
retry_button_brute_force = Button(result_frame_brute_force, text="Nouvelle tentative", command=retrybr, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button_brute_force.pack(side=tk.LEFT, padx=10)

# Frame pour afficher le résultat et le bouton "Nouvelle tentative" pour l'attaque par lookup table
result_frame_lookup_table = tk.Frame(main_frame, bg=BG_COLOR)
result_label_lookup_table = tk.Label(result_frame_lookup_table, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label_lookup_table.pack(side=tk.LEFT, padx=10)
password_label_lookup_table = tk.Label(result_frame_lookup_table, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label_lookup_table.pack(side=tk.LEFT)
retry_button_lookup_table = Button(result_frame_lookup_table, text="Nouvelle tentative", command=retrylookuptable, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button_lookup_table.pack(side=tk.LEFT, padx=10)   

# Frame pour afficher le résultat et le bouton "Nouvelle tentative" pour l'attaque Rainbow
result_frame_rainbow = tk.Frame(main_frame, bg=BG_COLOR)
rainbow_title=tk.Label(main_frame, text="Attaque arc en ciel", fg=ACCENT_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE, "bold"))
result_label_rainbow = tk.Label(result_frame_rainbow, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label_rainbow.pack(side=tk.LEFT, padx=10)
password_label_rainbow = tk.Label(result_frame_rainbow, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label_rainbow.pack(side=tk.LEFT)
retry_button_rainbow = Button(result_frame_rainbow, text="Nouvelle tentative", command=retryrnb, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button_rainbow.pack(side=tk.LEFT, padx=10)

# Label pour afficher la date et l'heure en haut à droite
date_label = tk.Label(main_frame, text=get_current_datetime(), fg="#00FF00", bg=BG_COLOR, font=("Courier", 12))
date_label.place(relx=1.0, rely=0, anchor='ne')
# Bouton "Retour" en bas à gauche
back_button = Button(main_frame, text="Retour", command=return_to_previous_screen, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
root.bind("<Escape>", lambda event: back_button.invoke())
back_button.place(relx=0, rely=1.0, anchor='sw')

# Style personnalisé pour la barre de progression
style = ttk.Style()
style.theme_use("default")
style.configure("Custom.Horizontal.TProgressbar", troughcolor=BG_COLOR, bordercolor=PROGRESS_COLOR, background=PROGRESS_COLOR, borderwidth=2)
#les déclaration pour tester mot de passe:
# Label et champ de saisie pour le mot de passe
label_test_password = tk.Label(main_frame, text="Entrez votre mot de passe :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
entry_test_password = tk.Entry(main_frame,width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, show="*")

# Bouton pour tester le mot de passe
test_password_button = Button(main_frame, text="Tester", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=test_password)

# Frame et label pour afficher le résultat
result_frame_test_password = tk.Frame(main_frame, bg=BG_COLOR)
result_label_test_password = tk.Label(result_frame_test_password, text="", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
result_label_test_password.pack(side=tk.TOP, padx=10)
reset_button_test_password = Button(result_frame_test_password, text="Réinitialiser", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=reset_password_test_interface)
reset_button_test_password.pack(side=tk.LEFT, padx=10)
#conseil frame
advice_frame = tk.Frame(main_frame, bg=BG_COLOR)
advice_title = tk.Label(advice_frame, text="Conseils pour un mot de passe sécurisé", fg=ACCENT_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE, "bold"))
advice_text = """
    - Utilisez au moins 12 caractères
    - Incluez des lettres majuscules, minuscules, des chiffres et des symboles
    - Évitez les mots de passe courants ou facilement devinables
    - Ne réutilisez pas le même mot de passe pour plusieurs comptes
    - Changez régulièrement vos mots de passe
    """
advice_label = tk.Label(advice_frame, text=advice_text, fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE), wraplength=450, justify="left")
#déclaration des frames du convertisseur:
md5_frame= tk.Frame(main_frame, bg=BG_COLOR)
entry_md5=tk.Entry(md5_frame,width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
entry_md5.place(relx=0.5, rely=0.4, anchor='center')
label_md5=tk.Label(md5_frame, text="entrez le mot que vous voulez haché en md5", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
label_md5.place(relx=0.5, rely=0.3, anchor='center')
label_result_md5=tk.Label(md5_frame, text="", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
md5_search_button=Button(md5_frame,text="Lancer",fg=FG_COLOR,bg=BUTTON_COLOR,font=custom_font, activeforeground=ACCENT_COLOR,command=md5_function)
md5_search_button.place(relx=0.5, rely=0.48, anchor='center')
label_copie=tk.Label(md5_frame,text="(hash copié)",fg=FG_COLOR,bg=BG_COLOR,font=FONT_FAMILY)
sha1_frame= tk.Frame(main_frame, bg=BG_COLOR)
entry_sha1=tk.Entry(sha1_frame,width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
label_sha1=tk.Label(sha1_frame, text="entrez le mot que vous voulez haché en sha1", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
label_result_sha1=tk.Label(sha1_frame, text="", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
sha1_search_button=Button(sha1_frame,text="Lancer",fg=FG_COLOR,bg=BUTTON_COLOR,font=custom_font, activeforeground=ACCENT_COLOR,command=sha1_function)
label_copie_sha1=tk.Label(sha1_frame,text="(hash copié)",fg=FG_COLOR,bg=BG_COLOR,font=FONT_FAMILY)
toggle_back_button(False)

'''root.bind_class("Entry", "<Control-c>", handle_shortcuts)
root.bind_class("Entry", "<Control-v>", handle_shortcuts)
root.bind_class("Entry", "<Control-a>", handle_shortcuts)'''
#update_frame()
root.mainloop()
