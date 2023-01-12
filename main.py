#from Crypto.Hash import keccak
from Crypto.Cipher import AES
from Crypto.Util import Counter
from backports.pbkdf2 import pbkdf2_hmac
import scrypt
import pyaes
import json

f = open('mnemonic_wallet.json')
data = json.load(f)
f.close()
type = data['crypto']['kdf']
# data = 'team engine square letter hero song dizzy scrub tornado fabric divert saddle'.encode('utf-8')
nonce = data['crypto']['cipherparams']['iv']
salt = bytes.fromhex(data['crypto']['kdfparams']['salt'])
ciphertext = bytes.fromhex(data['crypto']['ciphertext'])
N = data['crypto']['kdfparams']['n']
dklength = data['crypto']['kdfparams']['dklen']
if (type == "scrypt"):
    r = data['crypto']['kdfparams']['r']
    p = data['crypto']['kdfparams']['p']
ctr = Counter.new(128,initial_value=int.from_bytes(bytes.fromhex(nonce),'big'))
"""
-----------------------------------------------------password and MAC check
passwd = 'password'
k = keccak.new(digest_bits=256)
key = scrypt.hash(passwd.encode('utf-8'), salt, 16384, 8, 4, 32)
mac = data['crypto']['mac']
mac_key = key[-16:]
k.update(mac_key)
k.update(ciphertext)
mac_check = k.hexdigest()
if (mac_check == mac):
    print('key OK')
    """
# -------------------------------------------------- password crack
found = False
with open('pass_list.txt') as f:
    for line in f:
        if(type == 'pbkdf2'):
            key_try = pbkdf2_hmac("sha256", line.strip().encode('utf-8'), salt, N, dklength)
        else:
            key_try = scrypt.hash(line.strip().encode('utf-8'), salt, N, r, p, dklength)
        #aes = pyaes.AESModeOfOperationCTR(key_try[:16], pyaes.Counter(int.from_bytes(bytes.fromhex(nonce),'big')))
        #data_try = aes.decrypt(ciphertext[:16])
        # another library for implementing AES
        cipher = AES.new(key_try[:16], AES.MODE_CTR, counter=ctr)
        data_try = cipher.decrypt(ciphertext[:16])
        with open('bip39_wordlist.txt') as b:
            for word in b:
                if (data_try.find(word.strip().encode('utf-8')) != -1):
                    print('the password is: ' + line.strip())
                    # print('for the partial menmonic: ' + data_try.decode('utf-8'))
                    cipher = AES.new(key_try[:16], AES.MODE_CTR, counter=ctr)
                    data_try = cipher.decrypt(ciphertext)
                    print('complete mnemonic is: ' + data_try.decode('utf-8'))
                    found = True
                    break
        if (found):
        
            break
        b.close()
    f.close()