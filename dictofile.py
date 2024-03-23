import pickle
import hashlib

#this code turns a txt file into a dictionnary {key:hash,value:password}
password_dict={}
#init a dict

with open("liste.txt", 'r') as file:
    
    for line in file:
        
        value=line.strip()
        key=hashlib.md5(value.encode()).hexdigest()
        password_dict[key]=value
#save the dictionnary as a pickle file(byte stream)
    with open('password_dict.pkl', 'wb') as fp:
        pickle.dump(password_dict, fp)
