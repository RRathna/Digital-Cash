from BitVector import *
import sys
#from Crypto import Random
import random
import Crypto
from Crypto.PublicKey import RSA
import socket

IP = '127.0.0.1'
PORT = 5005
BUFFER_SIZE = 1024*64 # Normally 1024, but we want fast response
#MO_request = "abc"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', PORT))
MO =""
t = 0

RSA_n = 1024
n = 600 #MO no of bits
I_n = 440 # length of Identity in bits
M_n = 160 # length of message with Amount and Unique string
n_MoneyOrders = 5 #no of blinded messages to send to bank
n_SecretPairs = 4 # no of secret pairs to generate for each message

#load bank's RSA public key
with open('rsa.pub', 'r') as pub_file:
    pub_key = RSA.importKey(pub_file.read())

#Load bank's RSA private key
with open('rsa.pvt', 'r') as pvt_file:
    pvt_key = RSA.importKey(pvt_file.read())
    
def verify_secrets(I):
    Verify = True
    prev = I[0]
    for i in range(1,len(I)):
        if prev != I[i]: 
            Verify = False
            print i
            break
    return Verify
    

def UnblindMessage(Msg, b): #Msg - string, b - integer
    '''
    1. Splits Msg into msg + 4*secret pairs
    2. Unblinds each of the entities
    3. Returns msg and 4*Identites as calculated from the 4*secret pairs as strings
    '''

    vals = Msg.split(',')
    M_b = pvt_key.decrypt(int(vals[0])) #M_be = B_Msg**d,  where B_msg = M*(b_factor**e)%n ; Note ** = pow; Thus M_b = (M**d)*b_factor
    M_s = (M_b*b) % pub_key.n# M_signed = Msg**d as b_factor*b_inverse = 1; as b is b_inverse here
    e = pub_key.encrypt(M_s,None) #msg**(d*e); since d*e = 1, e = msg
    E = BitVector(intVal = e[0], size = 160)
    
    M = E.get_bitvector_in_ascii()
    I = []
    for i in range(1,len(vals),2):
        
        N1_b = pvt_key.decrypt(int(vals[i]))
        N1_s = (N1_b*b) % pub_key.n
        e = pub_key.encrypt(N1_s,None) #msg**(d*e); since d*e = 1, e = msg
        N1 = BitVector(intVal = e[0], size = 1024)

        N2_b = pvt_key.decrypt(int(vals[i+1]))
        N2_s = (N2_b*b) % pub_key.n
        e = pub_key.encrypt(N2_s,None) #msg**(d*e); since d*e = 1, e = msg
        N2 = BitVector(intVal = e[0], size = 1024)
        t = N1^N2
        I.append(t.get_bitvector_in_ascii())
    print "Identity string, after secret pair combination"
    for i in I : print i
    print "MO: " +M
    return M, I #returns msg and I[] as strings

def Sign(Msg,amt):
    msg = str(amt)+'-*-*-'
    vals = Msg.split(',')
    for i in range(0,len(vals)):
        M_b = pvt_key.decrypt(int(vals[i]))
        msg += " "+str(M_b)
    return msg
    
U_str = ["Hello"]
def process_MO(MO1,b_inv,T):
    MO_ = MO1.split(" ")
    b = b_inv.split(" ")
    amt = 0
    V = True
    M_ = ''
    for i in range(0, len(b)):
        b_i = b[i].split(",")
        print "The blinding factor"
        #print b_i
        M, I = UnblindMessage(MO_[int(b_i[0])], int(b_i[1]))
        V = verify_secrets(I)
        if V == False: return "Denied"
        if amt == 0:
            try:
                amt = int(M[:5])
            except:
                print("\n")
    
    if V == True:       
        with open("customerAcc.txt", 'r') as fl:
            line = fl.readlines()
        t = len(line)
        bal = int(line[t-1])
        print bal
        print amt
        print type(amt)
        if bal < amt:
            return "Denied"
        
        else : 
            bal = bal - amt
            print bal
            with open("customerAcc.txt", 'a') as fl:
                fl.write(str(bal))
                fl.write("\n")
        Msg = Sign(MO_[T],amt)
        return Msg

def search_UniqueString(Msg):
    import codecs
    M = Msg.split(",")
    e = pub_key.encrypt(int(M[0]),None)
    msg = BitVector(intVal = e[0], size = 160)
    MO_string = msg.get_bitvector_in_ascii()
    amt = int(MO_string[:5])
    
    print amt
    
    Unique_str = MO_string[5:]
    #Unique_str = t.encode('utf-8')
    print Unique_str
    
    for l in U_str:
        if l == MO_string: return True
    bal = 0
    #amt = int(Unique_str[:5])
    with open("merchantAcc.txt",'r') as fl:
        line = fl.readlines()
    t = len(line)
    with open("merchantAcc.txt",'a') as fl:
        if not line : bal = 0
        else : bal = int(line[t-1])
        Amt = bal + amt
        fl.write(str(Amt))
        fl.write('\n')
    
    U_str.append(MO_string)
    return False
    
    
while 1:
    
    data, addr = s.recvfrom(BUFFER_SIZE)
    #print Data
    if not data: 
        print("Bank Down, restart")
        break
    req = data.split('-*-*- ')
    
    if req[0] == "MO_request":
        print req[0]
        MO = req[1]
        t = random.randint(0,n_MoneyOrders-1)
        msg ="Except-*-*- "+ str(t)
        print msg
        s.sendto(msg,addr)

    if req[0] == "b-inverse":
        print req[0]
        b_inv = req[1]
        msg = process_MO(MO,b_inv,t)
        M = msg.split("-*-*- ")
        print M[0]
        s.sendto(msg,addr)
            
    elif req[0] == "MO_deposit":
        #1. req[1] has the (amt+unique string) + (one of the four pairs)
        #2. decrypt the first message and check for unique string in DB
        #3. if unique string not present already, credit amount, else reply not credited
        val = search_UniqueString(req[1])
        if val == False:
            msg = "credit_merchant"
            s.sendto(msg,addr)

        else:
            msg = "MO already used"
            s.sendto(msg,addr)

s.close()    

    