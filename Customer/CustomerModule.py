#Customer module
#by Rathna Ramesh

from BitVector import *
import sys
import random
import Crypto
from Crypto.PublicKey import RSA
import socket
import hmac

ind = 0

IP = '127.0.0.1'
PORT_bank = 5005
#server_address = ('localhost', 10000)
bank_addr = (IP,PORT_bank)
PORT_merchant = 5006
merch_addr = (IP, PORT_merchant)
BUFFER_SIZE = 1024*64
Request = ''

RSA_n = 1024
n = 600 #MO no of bits
I_n = 440 # length of Identity in bits
M_n = 160 # length of message with Amount and Unique string
n_MoneyOrders = 5 #no of blinded messages to send to bank
n_SecretPairs = 4 # no of secret pairs to generate for each message

#load bank's RSA public key
with open('rsa.pub', 'r') as pub_file:
    pub_key = RSA.importKey(pub_file.read())

def verify_secrets(I):
    Verify = True
    prev = I[0]
    for i in I:
        if prev != i: 
            Verify = False
            print i
            break
        prev = i
    return Verify

def EnforceLength(STRING, n):
    '''Make STRING of length by either ading 0 in the beginning or by only taking first n characters'''
    t = len(STRING)
    if t < n :
        for i in range(0, n-t):
            STRING = '0' + STRING
    if t > n :
        STRING = STRING[:n]
    return STRING


def CreateMoneyOrder(CUSTOMER_ID, CUST_NAME, CUST_ADDRESS, amount):
    '''create 5 unique money orders and one identity details in bits'''
    
#enforce the length on each item
    CUSTOMER_ID = EnforceLength(CUSTOMER_ID, 5)
    CUST_NAME = EnforceLength(CUST_NAME, 20)
    CUST_ADDRESS = EnforceLength(CUST_ADDRESS,30)
    AMOUNT = str(amount)
    if len(AMOUNT) > 5 :
        print ("Exceeds the allowed transaction limit of $99999 \n")
        return 0
    else :
        AMOUNT = EnforceLength(AMOUNT,5)
    
    #create five message packets and one identity byte string

    #convert each element into bit strings
    c_id = BitVector(textstring = CUSTOMER_ID)
    c_name = BitVector(textstring= CUST_NAME)
    c_addr = BitVector(textstring = CUST_ADDRESS)
    identity = c_id + c_name + c_addr
    

    msg = BitVector(textstring = AMOUNT)
    Msg = []
    #add unique string to each make unique message strings
    for i in range(0,n_MoneyOrders):
        UniqueByte = random.getrandbits(120) #returns an random int with 160 bits
        uv = BitVector( intVal = UniqueByte, size = 120)
        Msg.append(msg + uv)

    return Msg, identity #returns Msg as [] of bitVector, I as BitVector

 
def secret_splitting(I):
    N1 = []
    N2 = []
    for i in range(0, n_SecretPairs):
        n1 = random.getrandbits(I_n) #returns an random int with I_n bits
        N11 = BitVector(intVal = n1, size = I_n)
        N21 = I^N11 # ^ is XOR operation
        N1.append(N11)
        N2.append(BitVector(intVal = N21.int_val(),size = I_n))
   
    return N1,N2 #returns N1 and N2 as [] of BitVectors
   
def BlindMessages(msg , I):
    '''
    1. Finds secret splitting pairs for I
    2. Blinds msg and secret pairs
    3. Concatenates blinded msg and secret pairs of I as a string of comma separated ints to form Blinded Message
    4. Returns the Blinded message and inverse of blinding factor(int)
    '''
    
    #Find the secret splitting pairs for each of the 
    N1,N2 = secret_splitting(I)
    
    #randomly generate blinding factors
    r = random.getrandbits(1024) 
    #t = str(r)
    #find bitVector of blinding factor and its inverse
    b_factor = BitVector(intVal = r)
    b_inverse = b_factor.multiplicative_inverse(BitVector(intVal = pub_key.n)) #b_factor*b_inverse = 1; 

    #encrypt the blinding factor with Bank's public key
    encrypted = pub_key.encrypt(b_factor.int_val(), None) #blinding factor = "hello1"**e
    b_factor_pow_e = encrypted[0] #Blind_int = b_factor**e

    B_msg = (b_factor_pow_e * msg.int_val())% pub_key.n #B_msg = message * b_factor**e
    #B_msg = B_msg  # B_msg = message * (b_factor**e) % n ; Now msg is blinded
    
    B_N1 = []
    B_N2 = []
    for i in range(0, len(N1)):
        B_N1.append((b_factor_pow_e * N1[i].int_val())% pub_key.n)
        B_N2.append((b_factor_pow_e * N2[i].int_val()) % pub_key.n)
    
    Message = str(B_msg)
    for i in range(0, len(B_N1)):
        Message += ","+str(B_N1[i])+","+str(B_N2[i])

    return Message,b_inverse.int_val() #sends a string and integer

def UnblindMessage(Msg, b): #Msg - string, b - integer
    '''
    1. Splits Msg into msg + 4*secret pairs
    2. Unblinds each of the entities
    3. Returns msg and 4*Identites as calculated from the 4*secret pairs as strings
    '''

    vals = Msg.split(',')
    M_b = pvt_key.decrypt(int(vals[0])) #M_be = B_Msg**d,  where B_msg = M*(b_factor**e)%n ; Note ** = pow; Thus M_b = (M**d)*b_factor
    M_signed = (M_b*b) % pub_key.n# M_signed = Msg**d as b_factor*b_inverse = 1; as b is b_inverse here

    e = pub_key.encrypt(M_signed,None) #msg**(d*e); since d*e = 1, e = msg
    E = BitVector(intVal = e[0], size = M_n)
    M = E.get_bitvector_in_ascii()
    I = []
    for i in range(1,len(vals),2):
        
        N1_b = pvt_key.decrypt(int(vals[i]))
        N1_s = (N1_b*b) % pub_key.n
        e = pub_key.encrypt(N1_s,None) #msg**(d*e); since d*e = 1, e = msg
        N1 = BitVector(intVal = e[0], size = I_n)

        N2_b = pvt_key.decrypt(int(vals[i+1]))
        N2_s = (N2_b*b) % pub_key.n
        e = pub_key.encrypt(N2_s,None) #msg**(d*e); since d*e = 1, e = msg
        N2 = BitVector(intVal = e[0], size = I_n)
        t = N1^N2
        I.append(t.get_bitvector_in_ascii())

    return M, I #returns msg and I[] as strings

def get_b_inverses(b,t):
    #b_ = b.split(",")
    b_inverse ="b-inverse-*-*-"
    for i in range(0,n_MoneyOrders):
        if i != t:
            b_inverse += " "+str(i)+"," +str(b[i])
        else: print i
    return b_inverse


def Multiply_inverse(Msg, b, amount): # Msg - string, b - integer
    vals = Msg.split(' ')
    t = EnforceLength(str(amount), 5)
    M_signed = t + '-*-*-' 
    l = [int(v) for v in vals]
    for i in range(0,len(l)):
        m = (l[i]*b) % pub_key.n
        M_signed += ' ' +str(m)
        
    return M_signed 

def decrpyt_amount(mess):
    encrypted = pub_key.encrypt(int(mess), None) #blinding factor = "hello1"**e
    t = str(encrypted[0])
    return t
    
def BitCommit (message, key):
    from hashlib import sha1
    
    hashed = hmac.new(key, message, sha1)

    # The signature
    return hashed.digest().encode("base64").rstrip('\n')
    

while 1:
    mode = raw_input(" To make MO, press 1; to send last created MO to Merchant, press 2 :")
    
    if mode == '1':
        a = raw_input("Enter the 5- digit Account No: ")
        b = raw_input("Enter your Name(max 20 chars): ")
        c = raw_input("Enter your email ID (max 30 chars): ")

        amount = input("Enter the amount to create MO for (less than $99999): ")

        Msg, Identity = CreateMoneyOrder(a,b,c,amount)
        m = [None]*n_MoneyOrders
        b = [None]*n_MoneyOrders

        for i in range(0,n_MoneyOrders):
            m[i],b[i] = BlindMessages(Msg[i], Identity)
        Message = "MO_request-*-*-" #framing request to bank
        for i in range(0,n_MoneyOrders):
            Message +=" "+m[i]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(Message,bank_addr)
        d,add = s.recvfrom(BUFFER_SIZE)
        k = d.split('-*-*- ')
        print k[0]
        ind = int(k[1])
        b_inverse = get_b_inverses(b,int(k[1]))
        print b_inverse
        #send blinding factors of the asked MO numbers to bank
        s.sendto(b_inverse,bank_addr)
        #recieve signed MO from bank
        MO, add = s.recvfrom(BUFFER_SIZE)
        req = MO.split("-*-*- ")
        print (req[0])
        #print (req[1])
        if MO != "Denied":
            MO_signed = Multiply_inverse(req[1],b[ind],amount)
            with open('Unused_MO.txt', 'a') as fh:
                fh.write(MO_signed)
                fh.write("\n")
        else: print ("MO request rejected!")
        s.close()
        
    elif mode == '2':
        with open('Unused_MO.txt', 'r') as fh:
            line = fh.readlines()
        #print line
        if not line: print("No MOs to send, please select Mode = 1 next")
        else:
            Request = line[0]
            line = line[1:]
            with open('Unused_MO.txt', 'w') as fh:
                for l in line: fh.write(l)
            with open('Used_MO.txt', 'a') as fh:
                fh.write(Request)
                fh.write("\n")
            d = Request.split(" ")
            Message = decrpyt_amount(d[1]) #the plaintext MO amt+ Unique string is hashed and sent
            #do commitment before sending actual message
            key = random.randint(0,1234)
            key = str(key)
            print BitVector(intVal = int(Message), size = 1024).get_bitvector_in_ascii()
            
            hash_val = BitCommit (Message, key)
            Hash_and_key = hash_val + ','+key
            print Hash_and_key
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(Hash_and_key,merch_addr)
            ii,add = s.recvfrom(BUFFER_SIZE)
            print ii
            p = ii.split(",")
            Msg_pairs = d[1] + "," + d[2+int(p[0])]+ "," + d[2+int(p[1])]+ "," + d[2+int(p[2])]+ "," + d[2+int(p[3])]#bad hard code on number of secret pairs, got to change
            s.sendto(Msg_pairs,merch_addr)
            op, add = s.recvfrom(BUFFER_SIZE)
            print op
            s.close()
            
