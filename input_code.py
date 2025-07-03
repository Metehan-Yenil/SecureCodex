from flask import Flask, redirect, request
app = Flask(__name__)
@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request, check if it contains a valid domain, and 
    then redirect to the target URL
    '''
    target = request.args.get('target', '')
    if target.startswith('https://') and ""example.com"" in target:
        return redirect(target)
    else:
        return ""Invalid target""
user_input1 = input("Komut girin: ")
os.system(user_input1)   
import pickle
data = input("Serileştirilmiş veri: ")
obj = pickle.loads(data.encode())
import shlex
safe_input = shlex.quote(input("Komut girin: "))
subprocess.run(["ls", safe_input], shell=False)
import os
os.system(input('Komut girin: '))