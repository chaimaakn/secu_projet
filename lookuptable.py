import hashlib
import pickle

#program that searches for the correspondant hash using a dictionnary
pw=input("enter the password:")

pwhash=hashlib.md5(pw.encode()).hexdigest()
#prints the hash of the password we want to crack
print(pwhash)

#we open the pickle file and it returns to its original form as a dictionnary
with open('password_dict.pkl', 'rb') as fp:
    password_dic = pickle.load(fp)

#we look for the hash in the dictionnary
if pwhash in password_dic:
    print("Password found!")
    print("The password is:", password_dic[pwhash])
else:
    print("Password not found")
    
 
        
