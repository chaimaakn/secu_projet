import tkinter as tk
from tkinter import ttk, messagebox, font
from tqdm import tqdm
from tkmacosx import Button
import hashlib
import time
from datetime import datetime
import string
import itertools
import sys 
import pickle

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

# Fonction pour faire clignoter les points
def blink_dots(label, delay=500):
    def show_dots(dots):
        label.config(text="Patienter" + dots)
        label.after(delay, show_dots, dots[1:] + dots[:1])

    show_dots("...")




CARACTERES = string.ascii_letters + string.digits + string.punctuation

# Fonction pour calculer le hachage MD5 d'un mot
def md5(mot):
    return hashlib.md5(mot.encode()).hexdigest()

# Fonction pour tester si un mot correspond au hachage
def est_bon_mot(mot, hash_a_trouver):
    return md5(mot) == hash_a_trouver

# Fonction pour trouver le bon mot
def trouver_bon_mot(hash_a_trouver):
    longueur = 1
    start_time = time.time()  # Enregistrer le temps de départ
    mots_testes = 0
    while True:
        for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
            mots_testes += 1
            if mots_testes % 10000 == 0:
                print(f"Mots testés : {mots_testes}")
                sys.stdout.flush()
             
            if est_bon_mot(mot, hash_a_trouver):
                end_time = time.time()  # Enregistrer le temps de fin
                temps_ecoule = end_time - start_time
                return mot, temps_ecoule
            result_label_brute_force.config(text=f" {mot}",fg=FG_COLOR)
            root.update()    
        longueur += 1

# Fonction pour permettre à l'utilisateur d'entrer un hash et récupérer le mot correspondant
def retrouver_mot(hash_input):
    
    if len(hash_input) != 32 or not all(c in string.hexdigits for c in hash_input):
        print("Le hash entré n'est pas valide.")
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return
    bon_mot_trouve, temps_ecoule = trouver_bon_mot(hash_input)
    if bon_mot_trouve:
        
        retry_button_brute_force.pack(side=tk.LEFT, padx=10)
        result_label_brute_force.config(text=f"Le mot est: {bon_mot_trouve} \n trouvé en {temps_ecoule:.6f} secondes", fg=FG_COLOR)

        
    else:
        messagebox.showinfo("Information", "Aucun mot n'a été trouvé.")


def show_brute_force_interface():
    global entry_brut_force 
    global current_frame
    global start_brute_force_button
    # Cacher toutes les autres frames
    hide_all_frames()

    # Afficher l'interface pour l'attaque par force brute
    
    label_brute_force.place(relx=0.5, rely=0.3, anchor='center')
    entry_brut_force.place(relx=0.5, rely=0.4, anchor='center')
    start_brute_force_button.place(relx=0.5, rely=0.5, anchor='center') 
    result_frame_brute_force.place(relx=0.5, rely=0.6, anchor='center')
    result_label_brute_force.pack(pady=10)
    password_label_brute_force.pack(side="top", padx=10, pady=5)
    retry_button_brute_force.pack(pady=15)
    retry_button_brute_force.pack_forget()
    
    back_button_brute_force.place(relx=0, rely=1.0, anchor='sw')
    current_frame = result_frame_brute_force
    toggle_back_button(True)
    
def run_brute_force():
    
    try:
       global start_brute_force_button
       global entry_brut_force
       hashed_password = entry_brut_force.get().strip()
       
       if not hashed_password:
            messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.")
            return
       
       retrouver_mot(hashed_password)
       
       
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur s'est produite : {e}")     
# Variable pour stocker la valeur actuelle de la barre de progression
current_progress = 0

# Fonction pour afficher/cacher le bouton "Retour"
def toggle_back_button(show):
    if show:
        back_button.place(relx=0, rely=1.0, anchor='sw')
    else:
        back_button.place_forget()
        back_button_brute_force.place_forget()
        back_button_lookup_table.place_forget()

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
    global current_frame
    hide_all_frames()  # Cacher toutes les frames

    # Afficher l'interface de l'attaque par dictionnaire
    label_hashed_password.place(relx=0.5, rely=0.30, anchor='center')
    entry_hashed_password.place(relx=0.5, rely=0.4, anchor='center')
    crack_button.place(relx=0.5, rely=0.5, anchor='center')
    current_frame = label_hashed_password
    toggle_back_button(True)


# Fonction pour retourner à l'écran précédent
def return_to_previous_screen():
    global current_frame
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
        back_button_brute_force.place_forget()
        result_frame_brute_force.place_forget()
        result_label_brute_force.place_forget()
        password_label_brute_force.place_forget
        entry_brut_force.place_forget()
        label_brute_force.place_forget()
        start_brute_force_button.place_forget()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = attack_buttons_frame
        toggle_back_button(False)
    elif current_frame == result_frame_lookup_table:
        back_button_lookup_table.place_forget()
        result_frame_lookup_table.place_forget()
        result_label_lookup_table.place_forget()
        password_label_lookup_table.place_forget
        entry_lookup_table.place_forget()
        label_lookup_table.place_forget()
        start_lookup_table_button.place_forget()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = attack_buttons_frame
        toggle_back_button(False)    
    elif current_frame in (label_hashed_password, entry_hashed_password, crack_button):
        hide_password_entry()
        attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = attack_buttons_frame
        toggle_back_button(False)  # Cacher le bouton "Retour"
    elif current_frame == attack_buttons_frame:
        pass

# Fonction pour cracker le mot de passe
def crack_password():
    global current_frame, current_progress
    hashed_password = entry_hashed_password.get().strip()
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return
    if len(hashed_password) != 32 or not all(c in string.hexdigits for c in hashed_password):
        print("Le hash entré n'est pas valide.")
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return
    hide_all_frames()  # Cacher toutes les frames
   
    # Cacher tous les widgets sauf la barre de progression et le label clignotant
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()
    result_frame.place_forget()

    with open("mots.txt", "r") as file:
        words = [line.strip() for line in file]

    progress_bar.config(maximum=100)
    progress_bar.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    percentage_label.place(relx=0.5, rely=0.28, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    blink_label.place(relx=0.5, rely=0.45, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas
    blink_dots(blink_label)  # Démarrer le clignotement des points
    current_frame = progress_bar
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
    if current_frame==progress_bar:
        for word in words:
            md5_hash = hashlib.md5(word.encode()).hexdigest()
            if hashed_password == md5_hash:
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
    global current_frame, current_progress
    hashed_password = entry_lookup_table.get().strip()
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return
    if len(hashed_password) != 32 or not all(c in string.hexdigits for c in hashed_password):
        print("Le hash entré n'est pas valide.")
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return
    hide_all_frames()

    with open("password_dict.pkl", "rb") as file:
         password_dic = pickle.load(file)

    if hashed_password in password_dic:
        result_label_lookup_table.config(text=f"Le mot de passe est :", fg=FG_COLOR)
        password_label_lookup_table.config(text=password_dic[hashed_password], fg=FG_COLOR)
        result_frame_lookup_table.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
        retry_button_lookup_table.pack(side=tk.LEFT, padx=10)
        current_frame = result_frame_lookup_table
        toggle_back_button(False)
        
    else:
        result_label_lookup_table.config(text="Tentative échouée", fg=ACCENT_COLOR)
        password_label_lookup_table.config(text="")
        result_frame_lookup_table.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
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
    result_label_lookup_table.pack(pady=10)
    password_label_lookup_table.pack(side="top", padx=10, pady=5)
    retry_button_lookup_table.pack(pady=15)
    retry_button_lookup_table.pack_forget()
    
    back_button_lookup_table.place(relx=0, rely=1.0, anchor='sw')
    current_frame = result_frame_lookup_table
    toggle_back_button(True)


# Fonction pour réinitialiser l'interface
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


# Obtenir la date et l'heure actuelles
def get_current_datetime():
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return date_time


# Configuration de la fenêtre principale
root = tk.Tk()
root.title("Attaque par dictionnaire")
root.configure(bg=BG_COLOR)
root.config(highlightbackground="#00ff00", highlightcolor="#00ff00", highlightthickness=0.5)
root.geometry("550x450")  # Définir la taille de la fenêtre

# Obtenir les dimensions de la fenêtre
window_width = root.winfo_reqwidth()
window_height = root.winfo_reqheight()

# Calculer les coordonnées pour centrer la fenêtre
position_right = int(root.winfo_screenwidth()/2 - window_width/2)
position_down = int(root.winfo_screenheight()/2 - window_height/2)

# Définir la position de la fenêtre au milieu de l'écran
root.geometry("+{}+{}".format(position_right, position_down))

# Ajout d'une marge à côté des bordures
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Frame principale avec une marge
main_frame = tk.Frame(root, bg=BG_COLOR)
main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

# Police personnalisée
custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Frame pour les boutons d'attaque
attack_buttons_frame = tk.Frame(main_frame, bg=BG_COLOR)
attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur

# Boutons pour les différentes attaques
attack_dictionary_button = Button(attack_buttons_frame, text="Attaque par dictionnaire", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR, command=show_dictionary_attack)
attack_dictionary_button.pack(pady=10)

brute_force_button = Button(attack_buttons_frame, text="Brute Force", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR, command=show_brute_force_interface)
brute_force_button.pack(pady=10)

rainbow_attack_button = Button(attack_buttons_frame, text="Rainbow Attack", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
rainbow_attack_button.pack(pady=10)

lookup_table_button = Button(attack_buttons_frame, text="Lookup Table", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR,command=show_lookup_table)
lookup_table_button.pack(pady=10)

# Label pour le mot de passe haché
label_hashed_password = tk.Label(main_frame, text="Entrez le mot de passe haché (MD5) :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)

# Entrée pour le mot de passe haché
entry_hashed_password = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)

# Bouton pour cracker le mot de passe
crack_button = Button(main_frame, text="Cracker le mot de passe", command=crack_password, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
#Declaration brut force 
label_brute_force = tk.Label(main_frame, text="Entrez votre mot de passe haché (MD5) :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
start_brute_force_button = Button(main_frame, text="Rechercher", command=run_brute_force, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, width=150)
entry_brut_force = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
back_button_brute_force = Button(main_frame, text="Retour", command=return_to_previous_screen, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)

#Declaration lookup table 
label_lookup_table = tk.Label(main_frame, text="Entrez votre mot de passe haché (MD5) :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)
start_lookup_table_button = Button(main_frame, text="Rechercher", command=run_lookup_table, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, width=150)
entry_lookup_table = tk.Entry(main_frame, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)
back_button_lookup_table = Button(main_frame, text="Retour", command=return_to_previous_screen, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)

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
#declaration des frame de brut force j'ai testé les tiennes mais elle me génére pas les résultats que je veux puisque elle sont modelé pour tes fonctions alors j'ai crée les mienne sorry :(
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

# Label pour afficher la date et l'heure en haut à droite
date_label = tk.Label(main_frame, text=get_current_datetime(), fg="#00FF00", bg=BG_COLOR, font=("Courier", 12))
date_label.place(relx=1.0, rely=0, anchor='ne')

# Bouton "Retour" en bas à gauche
back_button = Button(main_frame, text="Retour", command=return_to_previous_screen, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
back_button.place(relx=0, rely=1.0, anchor='sw')

# Style personnalisé pour la barre de progression
style = ttk.Style()
style.theme_use("default")
style.configure("Custom.Horizontal.TProgressbar", troughcolor=BG_COLOR, bordercolor=PROGRESS_COLOR, background=PROGRESS_COLOR, borderwidth=2)


# Afficher le bouton "Retour" par défaut
toggle_back_button(False)

root.mainloop()