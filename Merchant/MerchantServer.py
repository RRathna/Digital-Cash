# Merchant
from BitVector import *
import sys
#from Crypto import Random
import random
import Crypto
from Crypto.PublicKey import RSA
import socket
import hmac

with open('rsa.pub', 'r') as pub_file:
    pub_key = RSA.importKey(pub_file.read())
IP = '127.0.0.1'
PORT_bank = 5005
#server_address = ('localhost', 10000)
bank_addr = (IP,PORT_bank)
# Selects random pairs and sends to the customer
def RandomSelector ():

    MyList = []

    x = random.randint (0, 1)
    MyList.append (str (x))
    x = random.randint (2, 3)
    MyList.append (str (x))
    x = random.randint (4, 5)
    MyList.append (str (x))
    x = random.randint (6, 7)
    MyList.append (str (x))

    MyStr = ",".join (MyList)
    return MyStr

# The below module sends the data it recieved from the Customer
def SendToBank (CustData):
    IP = '127.0.0.1'
    bank_port = 5005
    BUFFER_SIZE = 1024*64
    bank_addr = (IP, bank_port)

    BankData = "MO_Desposit" + "-*-*- " + CustData
    print (BankData)

    BankSoc = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
    BankSoc.sendto (BankData, bank_addr)
    data, addr = BankSoc.recvfrom (BUFFER_SIZE)

    print ("Recieved the following acknowledgement from Bank: " + str (data))

def BitCommit (message, key):
    from hashlib import sha1
    
    hashed = hmac.new(key, message, sha1)

    # The signature
    return hashed.digest().encode("base64").rstrip('\n')
    

# This module verifies the value of the hash against the original message
def Verify (hash_input, hash_key, hash_data):
    
    hashed = BitCommit (hash_input, hash_key)
    print "calculated Hash :"
    print hashed
    if (hash_data == hashed):
        return True

    else : return False

def decrpyt_amount(mess):
    encrypted = pub_key.encrypt(int(mess), None) #blinding factor = "hello1"**e
    t = str(encrypted[0])
    return t


def MerchantMain ():
    IP = '127.0.0.1'
    PORT = 5006
    BUFFER_SIZE = 1024*64

    MerSoc = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
    MerSoc.bind (('', PORT))

    while True:
        
        data, addr = MerSoc.recvfrom (BUFFER_SIZE)
        d = data.split(",")
        hash_op = d[0]
        key = d[1] #hash output and key recieved
        print data
        SendStr = RandomSelector()
        print SendStr
        MerSoc.sendto (SendStr, addr) #send the partial pairs needed from the customer
        
        message, add = MerSoc.recvfrom (BUFFER_SIZE)
        #print message
        mess = message.split(',')
        hash_ip = decrpyt_amount(mess[0])
        #hash_ip = str()
        print hash_ip
        verify = Verify (hash_ip, key, hash_op)
        print ("Verification Status: " + str (verify))
        message = "MO_deposit-*-*- "+message
        if verify == True: 
            MerSoc.sendto(message,bank_addr)
            data, addr = MerSoc.recvfrom (BUFFER_SIZE)
            print ("Received from Bank: " + str (data))
            MerSoc.sendto(data,add)
        else : MerSoc.sendto("Cheater-Hash&input mismatch!",addr)

        
MerchantMain()
