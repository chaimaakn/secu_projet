import pickle
import hashlib

password_dict={}


with open('C:\\Users\\meriem\\Downloads\\liste.txt', 'r') as file:
    
    for line in file:
        
        value=line.strip()
        key=hashlib.md5(value.encode()).hexdigest()
        password_dict[key]=value
    
    with open('password_dict.pkl', 'wb') as fp:
        pickle.dump(password_dict, fp)