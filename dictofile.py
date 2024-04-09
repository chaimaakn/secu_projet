import pickle
import hashlib

#this code turns a txt file into a dictionnary {key:hash,value:password}
password_dict={}
#init a dict

with open("liste.txt", 'r') as file:
    
    for line in file:
        
        value=line.strip()
        #key=hashlib.md5(value.encode()).hexdigest()   #pour créer la tqble de md5
        key=hashlib.sha1(value.encode()).hexdigest()   #pour créer la tqble de sha1
        password_dict[key]=value
#save the dictionnary as a pickle file(byte stream)
    with open('password_dict_sha1.pkl', 'wb') as fp:
        pickle.dump(password_dict, fp)
