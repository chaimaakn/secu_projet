import hashlib
import pickle


pw=input("enter the password:")

pwhash=hashlib.md5(pw.encode()).hexdigest()

print(pwhash)

with open('password_dict.pkl', 'rb') as fp:
    password_dic = pickle.load(fp)


if pwhash in password_dic:
    print("Password found!")
    print("The password is:", password_dic[pwhash])
else:
    print("Password not found")
    
 
        
