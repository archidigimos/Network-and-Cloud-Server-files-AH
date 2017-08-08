from autobahn.twisted.websocket import WebSocketServerProtocol, \
    WebSocketServerFactory
import sqlite3 as lite
import sys

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
import random, string
from random import randint
from threading import Timer


stateBLEd = {}

tubelightStateBLEd = {}
fanStateBLEd = {}

webClients={}
bleStateCheck={}
Client_Android_aes_object={}
connectdb={}
shutdown={}
client=0;
randomString=""
hwSessionKey=""
tubelightState="TL_OFF"
fanState="FAN_OFF"
Android_client_id=""
bleConnectionState="Disconnected"
con = lite.connect('database.db')
cur = con.cursor()
key = 'aswesdrftgrfdeyretgfrytghtyuij'
shutdown_case = 0

# First, read in from the private key file
key1 = open('private_key.pem', 'r').read()
 
# Parse the key file
rsakey = RSA.importKey(key1)
 
# Apply the padding settings
rsakey = PKCS1_OAEP.new(rsakey)

#----------------------------------------------
#Hardware to server control string decode 
#----------------------------------------------
def state_decode(tubelight_state_input,fan_state_input):
    if tubelight_state_input=="turnup":
        tubelightState_o= "TL_ON"
    elif tubelight_state_input=="turndown":
        tubelightState_o= "TL_OFF"
    if fan_state_input=="turndown":
        fanState_o= "FAN_OFF"
    elif fan_state_input=="turnupone":
        fanState_o= "FAN_ON_1"
    elif fan_state_input=="turnuptwo":
        fanState_o= "FAN_ON_2"
    elif fan_state_input=="turnupthree":
        fanState_o= "FAN_ON_3"
    elif fan_state_input=="turnupfour":
        fanState_o= "FAN_ON_4"
    elif fan_state_input=="turnupfive":
        fanState_o= "FAN_ON_5"
    return tubelightState_o, fanState_o
#----------------------------------------------
#System shutdown function on BLE disconnection
#----------------------------------------------
def system_shutdown(hardware_identity):
    #print("Shutdown command succesfully sent to Hardware with hardware_ID: "+hardware_identity)
    count=5
    print("Shutdown command succesfully sent to Hardware with hardware_ID: "+hardware_identity)
    while (count!=0): 
        connectdb[hardware_identity] = lite.connect('database.db')
        shutdown[hardware_identity] = connectdb[hardware_identity].cursor()
        shutdown[hardware_identity].execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":hardware_identity})
        datahwSession_ = shutdown[hardware_identity].fetchone()
        hwsessionFetch = datahwSession_[1]
        inputString = "PrevSESSION-"+str(hwsessionFetch)
        cipherText = xor_strings(inputString, key)
        webClients[hardware_identity].sendMessage(cipherText)
        #-----------------------------------------------------------------------------------------------------
        hwsessionFetch = str(random_with_N_digits(7))
        shutdown[hardware_identity].execute("UPDATE AliveHomeHardwareAddress SET hwSession=? WHERE Hardware_Address=?",(hwsessionFetch,hardware_identity))
        inputString = "SESSION-"+hwsessionFetch
        cipherText = xor_strings(inputString, key)
        webClients[hardware_identity].sendMessage(cipherText)
        #------------------------------------------------------------------------------------------------------------
        controlData = "TL_OFF-FAN_OFF"
        cipherText = xor_strings(controlData, key)
        webClients[hardware_identity].sendMessage(cipherText)
        connectdb[hardware_identity].commit()
        count=count-1
#----------------------------------------------
#Random Number Generator
#----------------------------------------------
def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

#----------------------------------------------
#XOR Cipher
#----------------------------------------------
def xor_strings(s,t):
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

#----------------------------------------------
#AES Encryption Class
#----------------------------------------------
class AESCipher:

    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, message):
        message = self._pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

#-------------------------------------------------

#Websocket Class
#----------------------------------------------------

class MyServerProtocol(WebSocketServerProtocol):

    def onConnect(self, request):
        print("Client connecting: {0}".format(request.peer))

    def onOpen(self):
        print("WebSocket connection open.")

    def onMessage(self, payload, isBinary):
    	global stateBLEd
    	global tubelightStateBLEd
    	global fanStateBLEd
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
        else:
            with con:
                cur.execute("CREATE TABLE IF NOT EXISTS AliveHome (Username TEXT ,Password TEXT ,Hardware_ID TEXT ,LoginStatus TEXT, Latitude TEXT, Longitude TEXT, Session TEXT, Tubelight TEXT, Fan TEXT, Timeoutsettings INT, SharedSEncryptionPass TEXT);")
                cur.execute("CREATE TABLE IF NOT EXISTS AliveHomeHardwareAddress (Hardware_Address TEXT ,BLE_MAC_Address TEXT, hwSession TEXT, bleConnectionStatus TEXT, shutdownEnDis TEXT, bleTubelight TEXT, bleFan TEXT);")
                
                #Client detection region
                #---------------------------------------------------
                if payload[0:5]=="HSIGN" or payload[0:8]=="DEVSTATE" or payload[0:9]=="PROXIMITY" or payload[0:11]=="BLEDEVSTATE":
                    print("Text message received: {0}".format(payload.decode('utf8')))
                    data_parsed = payload.split("-")
                elif payload[0:4]=="ping":
                    data_parsed = payload.split("-")
                else:
                    try:
                        b64_decoded_message = base64.b64decode(payload)
                        # Use the private key to decrypt
                        RSAdecryptedStr = str(rsakey.decrypt(b64_decoded_message))
                    except:
                        RSAdecryptedStr = "None"
                    if RSAdecryptedStr == "None":
                        for andro_client in webClients.iterkeys():
                            if webClients[andro_client] == self:
                                cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":andro_client})
                                sharedPasskey =  cur.fetchone()
                                Android_client_id = andro_client
                                Client_Android_aes_object[Android_client_id] = AESCipher(sharedPasskey[9])
                                decrypted = Client_Android_aes_object[Android_client_id].decrypt(payload)
                                data_parsed = decrypted.split("-")
                                break
                        
                    else:
                        data_parsed = RSAdecryptedStr.split("-")

                #Transfer Layer Session id request
                #---------------------------------------------------
                if data_parsed[0]=="sessionRequest":
                    global randomString
                    randomString = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
                    #print("Random session generated: "+randomString)
                    cur.execute("UPDATE AliveHome SET Session=? WHERE Username=?",(str(randomString),data_parsed[1]))
                    #con.commit()
                    encrypted = Client_Android_aes_object[Android_client_id].encrypt("session-"+str(randomString))
                    self.sendMessage(str(encrypted))

                #New Hardware registration
                #---------------------------------------------
                if data_parsed[0]=="HSIGN":
                    cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data_parsed[1]})
                    hwdAdd = cur.fetchone()
                    if hwdAdd is None:
                        '''
                        cur.execute("INSERT INTO AliveHomeHardwareAddress VALUES (?, ?, ?, ?);",(data_parsed[1],data_parsed[2],"",bleConnectionState))
                        client_esp = data_parsed[1]
                        #-----------------------------------------------------------------------------------------------------------------------------
                        cur.execute("SELECT Username, Password, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings FROM AliveHome WHERE Hardware_ID=:Hardware_ID",{"Hardware_ID":data_parsed[1]})
                        timeoutCheck =  cur.fetchone()
                        bleStateCheck[data_parsed[1]]=Timer(int(timeoutCheck[8]),system_shutdown,[data_parsed[1]])
                        #-----------------------------------------------------------------------------------------------------------------------------
                        webClients[client_esp] = self
                        print("Hardware with hardware ID: "+data_parsed[1]+" succesfully registered!!!")
                        #self.sendMessage("Hardware with hardware ID: "+data_parsed[1]+" succesfully registered!!!")
                        datahwSession = str(random_with_N_digits(7))
                        cur.execute("UPDATE AliveHomeHardwareAddress SET hwSession=? WHERE Hardware_Address=?",(datahwSession,data_parsed[1]))
                        inputString = "SESSION-"+ datahwSession
                        cipherText = xor_strings(inputString, key)
                        self.sendMessage(cipherText)
                        '''
                        print("Your hardware with hardware ID: "+data_parsed[1]+" has not been registered in database yet. Contact Server Admin to register your hardware!!!")
                    else:
                    	stateBLEd[data_parsed[1]] = 0
                    	cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data_parsed[1]})
                        devStateAftBle = cur.fetchone()
                        tubelightStateBLEd[data_parsed[1]] = devStateAftBle[4]
                        fanStateBLEd[data_parsed[1]] = devStateAftBle[5]
                        client_esp = data_parsed[1]
                        #-----------------------------------------------------------------------------------------------------------------------------
                        cur.execute("SELECT Username, Password, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Hardware_ID=:Hardware_ID",{"Hardware_ID":data_parsed[1]})
                        timeoutCheck =  cur.fetchone()
                        bleStateCheck[data_parsed[1]]=Timer(int(timeoutCheck[8]),system_shutdown,[data_parsed[1]])
                        #-----------------------------------------------------------------------------------------------------------------------------
                        webClients[client_esp] = self
                        print("Hardware with hardware ID: "+data_parsed[1]+" logged in!!!")
                        #self.sendMessage("Hardware with hardware ID: "+data_parsed[1]+" already registered!!!")
                        datahwSession = str(random_with_N_digits(7))
                        cur.execute("UPDATE AliveHomeHardwareAddress SET hwSession=? WHERE Hardware_Address=?",(datahwSession,data_parsed[1]))
                        #con.commit()
                        inputString = "SESSION-"+ datahwSession
                        cipherText = xor_strings(inputString, key)
                        #cipherText = inputString
                        self.sendMessage(cipherText)
                    
                #BLE Connection Status to the Hardware
                #-------------------------------------------------
                if data_parsed[0]=="PROXIMITY":
                    cur.execute("SELECT Username, Password, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Hardware_ID=:Hardware_ID",{"Hardware_ID":data_parsed[1]})
                    data = cur.fetchone()
                    if data[0] in webClients:
                    	cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data[0]})
                        sharedPasskey =  cur.fetchone()
                        Android_client_id = data[0]
                        Client_Android_aes_object[Android_client_id] = AESCipher(sharedPasskey[9])
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt(data_parsed[0]+"-"+data_parsed[1]+"-"+data_parsed[2])
                        
                        webClients[data[0]].sendMessage(str(encrypted))
                    else:
	                    print("Android device with username "+data[0]+" not Found!!!")

                    cur.execute("UPDATE AliveHomeHardwareAddress SET bleConnectionStatus=? WHERE Hardware_Address=?",(data_parsed[2],data_parsed[1]))
                    if data_parsed[2]=="Disconnected":
                    	stateBLEd[data_parsed[1]] = 0
                        cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data_parsed[1]})
                        shutdownCommandEnableDisable = cur.fetchone()
                        #-----------------------------------------------------------------------------------------------------------------------------
                        if shutdownCommandEnableDisable[3]=="Enabled":
                            cur.execute("SELECT Username, Password, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Hardware_ID=:Hardware_ID",{"Hardware_ID":data_parsed[1]})
                            timeoutCheck =  cur.fetchone()
                            bleStateCheck[data_parsed[1]]=Timer(int(timeoutCheck[8]),system_shutdown,[data_parsed[1]])
                            print("Auto Shutdown for hardware ID: "+data_parsed[1]+" has been enabled. Thank you for being a responsible earthling :D ")
                            #-----------------------------------------------------------------------------------------------------------------------------
                            bleStateCheck[data_parsed[1]].start()
                        elif shutdownCommandEnableDisable[3]=="Disabled":
                            print("Auto Shutdown for hardware ID: "+data_parsed[1]+" disabled. Please enable it to save energy :(")
                    elif data_parsed[2]=="Connected":
                    	stateBLEd[data_parsed[1]] = 1
                        bleStateCheck[data_parsed[1]].cancel()
                        count=5
                        print("Last device state command for hardware ID: "+data_parsed[1]+" has been issued succesfully!!!")
                        while (count!=0): 
                            cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data_parsed[1]})
                            datahwSession_ = cur.fetchone()
                            hwsessionFetch = datahwSession_[1]
                            inputString = "PrevSESSION-"+str(hwsessionFetch)
                            cipherText = xor_strings(inputString, key)
                            webClients[data_parsed[1]].sendMessage(cipherText)
                            #-----------------------------------------------------------------------------------------------------
                            hwsessionFetch = str(random_with_N_digits(7))
                            cur.execute("UPDATE AliveHomeHardwareAddress SET hwSession=? WHERE Hardware_Address=?",(hwsessionFetch,data_parsed[1]))
                            inputString = "SESSION-"+hwsessionFetch
                            cipherText = xor_strings(inputString, key)
                            webClients[data_parsed[1]].sendMessage(cipherText)
                            #------------------------------------------------------------------------------------------------------------
                            #cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data_parsed[1]})
                            #devStateAftBle = cur.fetchone()
                            controlData = tubelightStateBLEd[data_parsed[1]]+"-"+fanStateBLEd[data_parsed[1]]
                            cipherText = xor_strings(controlData, key)
                            webClients[data_parsed[1]].sendMessage(cipherText)
                            count=count-1
                #New user registration
                #---------------------------------------------
                if data_parsed[0]=="NUS":
                    cur.execute("UPDATE AliveHome SET SharedSEncryptionPass=? WHERE Username=?",(data_parsed[5],data_parsed[1]))
                    Android_client_id = data_parsed[1]
                    Client_Android_aes_object[Android_client_id] = AESCipher(data_parsed[5])
                    #----------------------------------------------------------------------------------------------------------------------------
                    if data_parsed[2] == data_parsed[3]:
                        cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                        data =  cur.fetchone()
                        cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data_parsed[4]})
                        hwdAdd = cur.fetchone()
                        if hwdAdd is None:
                            print("Sorry!!! No such hardware of hardware id: "+data_parsed[4]+" have registered yet!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Sorry!!! No such hardware of hardware id: "+data_parsed[4]+" have registered yet!!!")
                            self.sendMessage(str(encrypted))
                        else:
                            if data is None:
                                cur.execute("SELECT Username, Password, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Hardware_ID=:Hardware_ID",{"Hardware_ID":data_parsed[4]})
                                hwId =  cur.fetchone()
                                if hwId is None:
                                    client_android = data_parsed[1]
                                    webClients[client_android] = self
                                    cur.execute("INSERT INTO AliveHome VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",(data_parsed[1],data_parsed[2],data_parsed[4],'True',"","","oewruthrfoqw","TL_OFF","TL_OFF",10,""))
                                    print("User "+data_parsed[1]+" successfully signed up!!!")
                                    encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-User "+data_parsed[1]+" successfully signed up!!!")
                                    self.sendMessage(str(encrypted))
                                    
                                else:
                                    print("Sorry!! Same hardware cannot be mapped to multiple Users!!!")
                                    encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Sorry!! Same hardware cannot be mapped to multiple Users!!!")
                                    self.sendMessage(str(encrypted))
                                    
                            else:
                                client_android = data_parsed[1]
                                webClients[client_android] = self
                                print("User " + data_parsed[1] + " already registered!!!")
                                encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-User " + data_parsed[1] + " already registered!!!")
                                self.sendMessage(str(encrypted))
                                
                    else:
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Both passwords don't match. ReEnter the passwords correctly!!!")
                        self.sendMessage(str(encrypted))
                        print("Both passwords don't match. Re-Enter the passwords correctly!!!")

                #Send data to Android from Hardware via Server [Websocket control status]
                #-------------------------------------------------------------------------
                if data_parsed[0]=="DEVSTATE":
                    cur.execute("SELECT Username, Password, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Hardware_ID=:Hardware_ID",{"Hardware_ID":data_parsed[1]})
                    data = cur.fetchone()
                    if data[0] in webClients:
                        tubelightState,fanState = state_decode(str(data_parsed[2]),str(data_parsed[3]))
                        if stateBLEd[data_parsed[1]] == 1:
                        	tubelightStateBLEd[data_parsed[1]] = tubelightState
                        	fanStateBLEd[data_parsed[1]] = fanState
                        cur.execute("UPDATE AliveHome SET Tubelight=? WHERE Hardware_ID=?",(tubelightState,data_parsed[1]))
                        cur.execute("UPDATE AliveHome SET Fan=? WHERE Hardware_ID=?",(fanState,data_parsed[1]))
                        #-----------------------------------------------------------------------------------------------------------------------------
                        cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data[0]})
                        sharedPasskey =  cur.fetchone()
                        Android_client_id = data[0]
                        Client_Android_aes_object[Android_client_id] = AESCipher(sharedPasskey[9])
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("VERIFY-"+str(data[2])+"-STATUS-"+tubelightState+"-"+fanState)
                        
                        webClients[data[0]].sendMessage(str(encrypted))
                        print("Data succesfully sent to Android User with username: "+data[0])
                        #self.sendMessage("Data succesfully sent to Android User with username: "+str(data[0]))
                    else:
                        #self.sendMessage("Android device not Found!!!")
                        tubelightState,fanState = state_decode(str(data_parsed[2]),str(data_parsed[3]))
                        if stateBLEd[data_parsed[1]] == 1:
                        	tubelightStateBLEd[data_parsed[1]] = tubelightState
                        	fanStateBLEd[data_parsed[1]] = fanState
                        cur.execute("UPDATE AliveHome SET Tubelight=? WHERE Hardware_ID=?",(tubelightState,data_parsed[1]))
                        cur.execute("UPDATE AliveHome SET Fan=? WHERE Hardware_ID=?",(fanState,data_parsed[1]))
                        print("Android device with username "+data[0]+" not Found!!!")
                #Send data to Android from Hardware via Server [Bluetooth 4.0 control status]
                #-------------------------------------------------------------------------
                if data_parsed[0]=="BLEDEVSTATE":
                    tubelightState,fanState = state_decode(str(data_parsed[2]),str(data_parsed[3]))
                    cur.execute("UPDATE AliveHomeHardwareAddress SET bleTubelight=? WHERE Hardware_Address=?",(tubelightState,data_parsed[1]))
                    cur.execute("UPDATE AliveHomeHardwareAddress SET bleFan=? WHERE Hardware_Address=?",(fanState,data_parsed[1]))

                #Send data to Hardware from Android User via Server
                #-------------------------------------------------
                if data_parsed[0]=="STATUS":
                    cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                    data = cur.fetchone()
                    sessionFetch = data[5]
                    if sessionFetch==data_parsed[2]:
                        cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                        data = cur.fetchone()
                        status = data[2]
                        if status == "True": 
                            if data[1] in webClients:
                                #--------------------------------------------------------------------------------------------------
                                cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                                dbonedata = cur.fetchone()
                                cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":dbonedata[1]})
                                datahwSession_ = cur.fetchone()
                                hwsessionFetch = datahwSession_[1]
                                inputString = "PrevSESSION-"+str(hwsessionFetch)
                                cipherText = xor_strings(inputString, key)
                                #cipherText = inputString
                                webClients[data[1]].sendMessage(cipherText)
                                #-----------------------------------------------------------------------------------------------------
                                hwsessionFetch = str(random_with_N_digits(7))
                                cur.execute("UPDATE AliveHomeHardwareAddress SET hwSession=? WHERE Hardware_Address=?",(hwsessionFetch,dbonedata[1]))
                                #con.commit()
                                inputString = "SESSION-"+hwsessionFetch
                                cipherText = xor_strings(inputString, key)
                                #cipherText = inputString
                                webClients[data[1]].sendMessage(cipherText)
                                #self.sendMessage(cipherText)
                                #------------------------------------------------------------------------------------------------------------
                                cipherText = xor_strings("STATE-enquiry", key)
                                #cipherText = "STATE-enquiry"
                                webClients[data[1]].sendMessage(cipherText)
                                print("Data succesfully sent to Hardware with hardware_ID: "+data[1])
                                #encrypted = crypto.encrypt("Data succesfully sent to Hardware with hardware_ID: "+str(data[1]))
                                #self.sendMessage(str(encrypted))
                                #--------------------------------------------------------------------------------------------------
                            else:
                                #self.sendMessage("NOTIFY-Hardware not connected!!!")
                                print("Hardware with hardware_ID "+data[1]+" not connected!!!")
                        elif status == "False":
                            print("User with username: "+data_parsed[1]+"Signup or Login first to enable communication!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Signup or Login first in order to enable communication!!!")
                            self.sendMessage(str(encrypted))
                    else:
                        print("Transfer layer session error!!! Reset server connection.")
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("Transfer layer session error!!! Reset server connection.")
                        self.sendMessage(str(encrypted))
                #--------------------------------------------------
                if data_parsed[0]=="CTRL":
                    cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                    data = cur.fetchone()
                    sessionFetch = data[5]
                    if sessionFetch==data_parsed[4]:
                        cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                        data = cur.fetchone()
                        if data[2] == "True":
                            if data[1] in webClients:
                                #--------------------------------------------------------------------------------------------------
                                cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                                dbonedata = cur.fetchone()
                                count_ctrl=3
                                while(count_ctrl!=0):
                                    cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":dbonedata[1]})
                                    datahwSession_ = cur.fetchone()
                                    hwsessionFetch = datahwSession_[1]
                                    inputString = "PrevSESSION-"+str(hwsessionFetch)
                                    cipherText = xor_strings(inputString, key)
                                    #cipherText = inputString
                                    webClients[data[1]].sendMessage(cipherText)
                                    #-----------------------------------------------------------------------------------------------------
                                    hwsessionFetch = str(random_with_N_digits(7))
                                    cur.execute("UPDATE AliveHomeHardwareAddress SET hwSession=? WHERE Hardware_Address=?",(hwsessionFetch,dbonedata[1]))
                                    #con.commit()
                                    inputString = "SESSION-"+hwsessionFetch
                                    cipherText = xor_strings(inputString, key)
                                    #cipherText = inputString
                                    webClients[data[1]].sendMessage(cipherText)
                                    #self.sendMessage(cipherText)
                                    #------------------------------------------------------------------------------------------------------------
                                    controlData = str(data_parsed[2])+"-"+str(data_parsed[3])
                                    cipherText = xor_strings(controlData, key)
                                    #cipherText = controlData
                                    webClients[data[1]].sendMessage(cipherText)
                                    count_ctrl=count_ctrl-1
                                print("Data succesfully sent to Hardware with hardware_ID: "+data[1])
                                #------------------------------------------------------------------------------------------------------------
                                #cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                                #deviceStatus = cur.fetchone()
                                #encrypted = crypto.encrypt("VERIFY-"+str(deviceStatus[2])+"-STATUS-"+deviceStatus[6]+"-"+deviceStatus[7])
                                ##encrypted = crypto.encrypt("Data succesfully sent to Hardware with hardware_ID: "+str(data[1]))
                                #self.sendMessage(str(encrypted))
                            else:
                                #self.sendMessage("NOTIFY-Hardware not connected!!!")
                                print("Hardware with hardware_ID "+data[1]+" not connected!!!")
                        elif data[2] == "False":
                            print("User with username: "+data_parsed[1]+"Signup or Login first to enable communication!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Signup or Login first in order to enable communication!!!")
                            self.sendMessage(str(encrypted))
                    else:
                        print("Transfer layer session error!!! Reset server connection.")
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("Transfer layer session error!!! Reset server connection.")
                        self.sendMessage(str(encrypted))
                #--------------------------------------------------
                if data_parsed[0]=="ENQ":
                    cur.execute("UPDATE AliveHome SET SharedSEncryptionPass=? WHERE Username=?",(data_parsed[2],data_parsed[1]))
                    Android_client_id = data_parsed[1]
                    Client_Android_aes_object[Android_client_id] = AESCipher(data_parsed[2])
                    #----------------------------------------------------------------------------------------------------------------------------
                        
                    cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                    data = cur.fetchone()
                    if data is None:
                        print("No such User of username: "+data_parsed[1]+" available!!!")
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("No such User of username: "+data_parsed[1]+" available!!!")
                        self.sendMessage(str(encrypted))
                    else:
                        cur.execute("SELECT BLE_MAC_Address, hwSession, bleConnectionStatus, shutdownEnDis, bleTubelight, bleFan FROM AliveHomeHardwareAddress WHERE Hardware_Address=:Hardware_Address",{"Hardware_Address":data[1]})
                        hwdAdd = cur.fetchone()
                        if hwdAdd is None:
                            print("No such hardware of HardwareId: "+data[1]+" available!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Sorry!!! No such hardware of hardware id: "+data_parsed[4]+" have registered yet!!!")
                            self.sendMessage(str(encrypted))
                            self.sendMessage("No such hardware of HardwareId: "+data[1]+" available!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("VERIFY-"+str(data[2])+"-BLEMAC-00:00:00:00:00:00")
                            self.sendMessage(str(encrypted))
                        else:
                            print("Password and Username verification status: "+data[2]+"BLEMAC: "+hwdAdd[0])
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("VERIFY-"+str(data[2])+"-BLEMAC-"+str(hwdAdd[0]))
                            self.sendMessage(str(encrypted))
                #--------------------------------------------------
                if data_parsed[0]=="LOGI":
                    cur.execute("UPDATE AliveHome SET SharedSEncryptionPass=? WHERE Username=?",(data_parsed[3],data_parsed[1]))
                    Android_client_id = data_parsed[1]
                    Client_Android_aes_object[Android_client_id] = AESCipher(data_parsed[3])
                    #----------------------------------------------------------------------------------------------------------------------------
                        
                    cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                    data = cur.fetchone()
                    if data is None:
                        print("No such User of username: "+data_parsed[1]+" available!!!")
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("No such User of username: "+data_parsed[1]+" available!!!")
                        self.sendMessage(str(encrypted))
                    else:
                        if data[2] == "False":
                            if data[0] == data_parsed[2]:
                                cur.execute("UPDATE AliveHome SET LoginStatus=? WHERE Username=?",('True',data_parsed[1]))
                                cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                                data =  cur.fetchone()
                                status = data[2]
                                if status == "True":
                                    client_android = data_parsed[1]
                                    webClients[client_android] = self
                                    print("User with username: "+data_parsed[1]+" logged in!!!")
                                    encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-User with username: "+data_parsed[1]+" logged in!!!")
                                    self.sendMessage(str(encrypted))
                            else:
                                print("Incorrect password provided by User: "+data_parsed[1])
                                encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-Incorrect password provided by User: "+data_parsed[1])
                                self.sendMessage(str(encrypted))
                        elif data[2] == "True":
                            cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                            credentials = cur.fetchone()
                            if data_parsed[2] == credentials[0]:
                                client_android = data_parsed[1]
                                webClients[client_android] = self
                                print("User with username: "+data_parsed[1]+" is already logged in!!!")
                                encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-User with username: "+data_parsed[1]+" is already logged in!!!")
                                self.sendMessage(str(encrypted))
                            elif data_parsed[2] != credentials[0]:
                                cur.execute("UPDATE AliveHome SET LoginStatus=? WHERE Username=?",('False',data_parsed[1]))
                #--------------------------------------------------
                if data_parsed[0]=="LOGO":
                    cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                    data = cur.fetchone()
                    sessionFetch = data[5]
                    if sessionFetch==data_parsed[2]:
                        cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                        data = cur.fetchone()
                        if data is None:
                            print("No such User of username: "+data_parsed[1]+" available!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-No such User of username: "+data_parsed[1]+" available!!!")
                            self.sendMessage(str(encrypted))
                        else:
                            if data[2] == "False":
                                if data_parsed[1] in webClients:
                                    del webClients[data_parsed[1]]
                                print("User with username: "+data_parsed[1]+" is already logged out!!!")
                                encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-User with username: "+data_parsed[1]+" is already logged out!!!")
                                self.sendMessage(str(encrypted))
                            elif data[2] == "True":
                                cur.execute("UPDATE AliveHome SET LoginStatus=? WHERE Username=?",('False',data_parsed[1]))
                                cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                                data =  cur.fetchone()
                                status = data[2]
                                if status == "False":
                                    if data_parsed[1] in webClients:
                                        del webClients[data_parsed[1]]
                                    print("User with username: "+data_parsed[1]+" logged out!!!")
                                    encrypted = Client_Android_aes_object[Android_client_id].encrypt("NOTIFY-User with username: "+data_parsed[1]+" logged out!!!")
                                    self.sendMessage(str(encrypted))
                    else:
                        print("Transfer layer session error!!! Reset server connection.")
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("Transfer layer session error!!! Reset server connection.")
                        self.sendMessage(str(encrypted))
                #--------------------------------------------------
                if data_parsed[0]=="LOCATION":
                    cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                    data = cur.fetchone()
                    sessionFetch = data[5]
                    if sessionFetch==data_parsed[4]:
                        cur.execute("SELECT Password, Hardware_ID, LoginStatus, Latitude, Longitude, Session, Tubelight, Fan, Timeoutsettings, SharedSEncryptionPass FROM AliveHome WHERE Username=:Username",{"Username":data_parsed[1]})
                        data = cur.fetchone()
                        if data is None:
                            print("No such User of username: "+data_parsed[1]+" available!!!")
                            encrypted = Client_Android_aes_object[Android_client_id].encrypt("No such User of username: "+data_parsed[1]+" available!!!")
                            self.sendMessage(str(encrypted))
                        else:
                            cur.execute("UPDATE AliveHome SET Latitude=? WHERE Username=?",(data_parsed[2],data_parsed[1]))
                            cur.execute("UPDATE AliveHome SET Longitude=? WHERE Username=?",(data_parsed[3],data_parsed[1]))
                    else:
                        print("Transfer layer session error!!! Reset server connection.")
                        encrypted = Client_Android_aes_object[Android_client_id].encrypt("Transfer layer session error!!! Reset server connection.")
                        self.sendMessage(str(encrypted))
                #--------------------------------------------------
                con.commit()

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))
        for client_conn in webClients.iterkeys():
            if webClients[client_conn] == self:
                print("Client "+client_conn+" disconnected!!!")
                del webClients[client_conn]
                break
#------------------------------------------------------------------
            

#Main function
#--------------------------------------------
if __name__ == '__main__':

    import sys

    from twisted.python import log
    from twisted.internet import reactor

    log.startLogging(sys.stdout)

    factory = WebSocketServerFactory(u"ws://192.168.0.104:80")
    #factory = WebSocketServerFactory(u"ws://192.168.8.100:80")
    factory.protocol = MyServerProtocol


    reactor.listenTCP(80, factory)
    reactor.run()

con.close()
del webClients
print("DB closed and Dict. deleted!!!")

#---------------------------------------------------------------
