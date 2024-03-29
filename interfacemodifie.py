
import tkinter as tk
from tkinter import ttk, messagebox, font
from tqdm import tqdm
from tkmacosx import Button
import hashlib
import time
from datetime import datetime
import itertools
import string

# Couleurs
BG_COLOR = "#000000"
FG_COLOR = "#00ff00"
ACCENT_COLOR = "#ff0000"
PROGRESS_COLOR = "#00ff00"
BUTTON_COLOR = "#000000"  # Couleur des boutons
BUTTON_ACTIVE_COLOR = "#004400"  # Couleur des boutons lorsqu'ils sont actifs

# Police de caractères
FONT_FAMILY = "Courier"
FONT_SIZE = 12

# Fonction pour faire clignoter les points
def blink_dots(label, delay=500):
    def show_dots(dots):
        label.config(text="Patienter" + dots)
        label.after(delay, show_dots, dots[1:] + dots[:1])

    show_dots("...")
#pour effacer le menu
def effacer_menu():
    attack_buttons_frame.destroy()
#fonction pour la force brut 
def run_brute_force():
    try:
       effacer_menu()
       CARACTERES = string.ascii_letters + string.digits + string.punctuation

       def md5(mot):
            return hashlib.md5(mot.encode()).hexdigest()

       def est_bon_mot(mot, hash_a_trouver):
            return md5(mot) == hash_a_trouver

       def trouver_bon_mot(hash_a_trouver):
           longueur = 1
           start_time = time.time()
           mots_testes = 0
           while True:
             for mot in (''.join(carac) for carac in itertools.product(CARACTERES, repeat=longueur)):
              if est_bon_mot(mot, hash_a_trouver):
                  end_time = time.time()  # Enregistrer le temps de fin
                  temps_ecoule = end_time - start_time
                  return mot, temps_ecoule
            # Mettre à jour la fenêtre principale avec chaque essai
              label_resultat.config(text=f" {mot}",fg="green")
              root.update()
             longueur += 1

       def retrouver_mot(hash_input):
         if len(hash_input) != 32 or not all(c in string.hexdigits for c in hash_input):
            return "Le hash entré n'est pas valide.", None
         bon_mot_trouve, temps_ecoule = trouver_bon_mot(hash_input)
         if bon_mot_trouve:
            return f"Le mot est: {bon_mot_trouve}", temps_ecoule
         else:
             return "Aucun mot n'a été trouvé.", None

       def rechercher_mot():
          hash_input = entry_hash.get().strip()
          resultat_text, temps_ecoule = retrouver_mot(hash_input)
          label_resultat.config(text=resultat_text)
          if temps_ecoule:
             label_temps.config(text=f"trouvé en : {temps_ecoule:.6f} secondes")
             bouton_reinitialiser.pack(side=tk.LEFT, padx=5)
             bouton_recherche.pack_forget()

       def reinitialiser():
         entry_hash.delete(0, tk.END)
         label_resultat.config(text="")
         label_temps.config(text="")
         bouton_reinitialiser.pack_forget()
         bouton_recherche.pack()

  # Création de l'interface graphique
   

# Frame pour centrer les widgets
       frame_centre = tk.Frame(root, bg='black')
       frame_centre.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

       label_hash = tk.Label(frame_centre, text="Entrez le hash MD5 :", fg="white", bg="black")
       label_hash.pack(pady=5)

       entry_hash = tk.Entry(frame_centre, width=40, bg='black', fg='white')
       entry_hash.pack(pady=5)

       bouton_recherche = tk.Button(frame_centre, text="Rechercher",activebackground=BUTTON_ACTIVE_COLOR ,command=rechercher_mot, bg='green')
       bouton_recherche.pack(pady=5)

# Frame pour positionner les résultats et le temps
       frame_resultat = tk.Frame(root, bg='black')
       frame_resultat.place(relx=0.5, rely=0.9, anchor=tk.S)

       label_resultat = tk.Label(frame_resultat, text="", fg="green", bg="black")
       label_resultat.pack(pady=5)

       label_temps = tk.Label(frame_resultat, text="", fg="green", bg="black")
       label_temps.pack(pady=5)

# Boutons pour fermer et réinitialiser
       bouton_reinitialiser = tk.Button(frame_resultat, text="Réinitialiser", command=reinitialiser, bg='blue', fg='white')

# Placer le bouton dans le frame_resultat mais le cacher initialement
       bouton_reinitialiser.pack_forget()

       root.mainloop()
 
       
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur s'est produite : {e}")
        
        
# Fonction pour afficher l'interface de l'attaque par dictionnaire
def show_dictionary_attack():
    # Masquer les boutons principaux
    attack_buttons_frame.place_forget()

    # Afficher l'interface de l'attaque par dictionnaire
    label_hashed_password.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    entry_hashed_password.place(relx=0.5, rely=0.4, anchor='center')  # Centrer en hauteur
    crack_button.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas

# Fonction pour cracker le mot de passe
def crack_password():
    hashed_password = entry_hashed_password.get().strip()
    if not hashed_password:
        messagebox.showerror("Erreur", "Veuillez entrer un mot de passe haché valide.", parent=root)
        return

    # Cacher tous les widgets sauf la barre de progression et le label clignotant
    label_hashed_password.place_forget()
    entry_hashed_password.place_forget()
    crack_button.place_forget()
    result_frame.place_forget()

    with open("mots.txt", "r") as file:
        words = [line.strip() for line in file]

    progress_bar.config(maximum=100)
    progress_bar.place(relx=0.5, rely=0.35, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    percentage_label.place(relx=0.5, rely=0.3, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le haut
    blink_label.place(relx=0.5, rely=0.45, anchor='center')  # Centrer en hauteur et ajuster légèrement vers le bas
    blink_dots(blink_label)  # Démarrer le clignotement des points

    for progress in tqdm(range(101), desc="Chercher...", unit="%", leave=False):
        progress_bar.step(1)
        percentage_label.config(text=f"{progress}%")
        root.update()
        time.sleep(0.05)

    progress_bar.stop()
    progress_bar.place_forget()  # Cacher la barre de progression
    percentage_label.place_forget()  # Cacher le label de pourcentage
    blink_label.place_forget()  # Cacher le label clignotant

    for word in words:
        md5_hash = hashlib.md5(word.encode()).hexdigest()
        if hashed_password == md5_hash:
            result_label.config(text=f"Le mot de passe est :", fg=FG_COLOR)
            password_label.config(text=word, fg=ACCENT_COLOR)
            result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur
            return

    result_label.config(text="Tentative échouée", fg=ACCENT_COLOR)
    password_label.config(text="")
    result_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur

# Fonction pour réinitialiser l'interface
def retry():
    # Cacher les éléments de la tentative précédente
    result_frame.place_forget()
    result_label.config(text="")
    password_label.config(text="")

    # Réinitialiser l'interface de l'attaque par dictionnaire
    show_dictionary_attack()

# Obtenir la date et l'heure actuelles
def get_current_datetime():
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return date_time

# Configuration de la fenêtre principale
root = tk.Tk()
root.title("Attaque par dictionnaire")
root.configure(bg=BG_COLOR)
root.geometry("500x400")  # Définir la taille de la fenêtre

# Obtenir les dimensions de la fenêtre
window_width = root.winfo_reqwidth()
window_height = root.winfo_reqheight()

# Calculer les coordonnées pour centrer la fenêtre
position_right = int(root.winfo_screenwidth()/2 - window_width/2)
position_down = int(root.winfo_screenheight()/2 - window_height/2)

# Définir la position de la fenêtre au milieu de l'écran
root.geometry("+{}+{}".format(position_right, position_down))

# Police personnalisée
custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Frame pour les boutons d'attaque
attack_buttons_frame = tk.Frame(root, bg=BG_COLOR)
attack_buttons_frame.place(relx=0.5, rely=0.5, anchor='center')  # Centrer en hauteur et en largeur

# Boutons pour les différentes attaques
attack_dictionary_button = Button(attack_buttons_frame, text="Attaque par dictionnaire", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR, command=show_dictionary_attack)
attack_dictionary_button.pack(pady=10)

brute_force_button = Button(attack_buttons_frame, text="Brute Force", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR,command=run_brute_force)
brute_force_button.pack(pady=10)

rainbow_attack_button = Button(attack_buttons_frame, text="Rainbow Attack", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
rainbow_attack_button.pack(pady=10)

lookup_table_button = Button(attack_buttons_frame, text="Lookup Table", fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
lookup_table_button.pack(pady=10)

# Label pour le mot de passe haché
label_hashed_password = tk.Label(root, text="Entrez le mot de passe haché (MD5) :", fg=FG_COLOR, bg=BG_COLOR, font=custom_font)

# Entrée pour le mot de passe haché
entry_hashed_password = tk.Entry(root, width=40, fg=FG_COLOR, bg=BG_COLOR, font=custom_font, highlightthickness=0.5)

# Bouton pour cracker le mot de passe
crack_button = Button(root, text="Cracker le mot de passe", command=crack_password, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)

# Barre de progression
progress_bar = ttk.Progressbar(root, length=400, mode="determinate", style="Custom.Horizontal.TProgressbar")

# Label pour afficher le pourcentage
percentage_label = tk.Label(root, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Label clignotant
blink_label = tk.Label(root, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)

# Frame pour afficher le résultat et le bouton "Nouvelle tentative"
result_frame = tk.Frame(root, bg=BG_COLOR)
result_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=FG_COLOR)
result_label.pack(side=tk.LEFT, padx=10)
password_label = tk.Label(result_frame, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
password_label.pack(side=tk.LEFT)
retry_button = Button(result_frame, text="Nouvelle tentative", command=retry, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
retry_button.pack(side=tk.LEFT, padx=10)

# Label pour afficher la date et l'heure en haut à droite
date_label = tk.Label(root, text=get_current_datetime(), fg="#00FF00", bg=BG_COLOR, font=("Courier", 12))
date_label.place(relx=1.0, rely=0, anchor='ne')

# Bouton "Retour" en bas à gauche
back_button = Button(root, text="Retour", command=root.destroy, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activebackground=BUTTON_ACTIVE_COLOR)
back_button.place(relx=0, rely=1.0, anchor='sw')

# Style personnalisé pour la barre de progression
style = ttk.Style()
style.theme_use("default")
style.configure("Custom.Horizontal.TProgressbar", troughcolor=BG_COLOR, bordercolor=PROGRESS_COLOR, background=PROGRESS_COLOR, borderwidth=2)

root.mainloop()

