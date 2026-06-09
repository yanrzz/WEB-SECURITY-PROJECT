import requests

url = "http://127.0.0.1:5000/login"
username = "admin"
passwords = ["salah1","salah2","salah3","salah4","salah5","salah6"]

for pwd in passwords:
    r = requests.post(url, data={"username":username,"password":pwd})
    if "terkunci" in r.text:
        print(f"TERKUNCI setelah {passwords.index(pwd)+1} percobaan")
        break
    else:
        print(f"Percobaan {passwords.index(pwd)+1}: gagal ({pwd})")