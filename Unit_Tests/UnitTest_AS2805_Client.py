import socket
import time
from datetime import datetime
import binascii
from random import randint

from Data_Structures.AS2805_Structs.AS2805Errors import *
from Data_Structures.AS2805_Structs.AS2805 import AS2805, ReadableAscii


class AS2895Client():

    # Configure the client
    #serverIP = "196.26.173.115"
    #serverPort = 50089
    def __init__(self):
        self.stan =   self.EFTPOS_0200_request()
        self.stan = str(randint(1,8000)).zfill(6)
        self.iso = AS2805(debug=False)
        self.retrieval_refrence_no = str(randint(1,900000000000)).zfill(12)
        self.stan = str(randint(1,8000)).zfill(6)
        self.stan = str(randint(1,8000)).zfill(6)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    serverIP = "127.0.0.1"
    serverPort = 19200
    numberEcho = 1
    timeBetweenEcho = 5 # in seconds
    atmid = ""
    bigEndian = True
    #bigEndian = False


    def Connect(self):
        self.s.connect(('127.0.0.1', 19200))
        self.s.settimeout(10.0)


    def __int__(self, atmid):
        self.atmid = atmid
        self.Process()



    def Alaric_Login(self):
        self.Connect()
        res = False
        d = datetime.now()
        iso = AS2805(debug=False)
        iso.setMTI('0800')
        iso.setBit(7, d.strftime("%m%d%H%M%S"))
        iso.setBit(11, self.stan)
        iso.setBit(12, d.strftime("%H%M%S"))
        iso.setBit(13, d.strftime("%m%d"))
        iso.setBit(70, '001')
        iso.setBit(41, self.atmid)

        try:

            print iso.dumpFields()
            message = iso.getNetworkISO()
            self.s.send(message)
            "Alaric_Login Request  = [%s]" % ReadableAscii(message)

            ans = self.s.recv(1024)
            print "Response  = %s" % ans
            isoAns = AS2805()
            isoAns.setNetworkISO(ans)
            v1 = isoAns.getBitsAndValues()
            for v in v1:
                print 'Bit %s of type %s with value = %s' % (v['bit'], v['type'], v['value'])

            if isoAns.getMTI() == '0810':
                if isoAns.getBit(39) == '00':
                    print "0800 Login sucessful"
                    res = True
                else:
                    print "0800 Response Code = %s, Login Failed" % (isoAns.getBit(39),)
            else:
                print "Could not login with 0800"
            self.s.close()
        except InvalidAS2805, ii:
            print ii

        return res


    def EFTPOS_0200_request(self):

        self.Connect()
        d = datetime.now()
        self.iso.setMTI('200')
        self.iso.setBit(2, '5062563893652986')
        self.iso.setBit(3, '001000')
        self.iso.setBit(4, '000000000000')
        self.iso.setBit(7, d.strftime("%m%d%H%M%S"))
        self.iso.setBit(11, self.stan)
        self.iso.setBit(12, d.strftime("%H%M%S"))
        self.iso.setBit(13, d.strftime("%m%d"))
        self.iso.setBit(14, '1609')
        self.iso.setBit(15, d.strftime("%m%d"))
        self.iso.setBit(18, '8754')
        self.iso.setBit(22, '071')
        self.iso.setBit(23, '877')
        self.iso.setBit(25, '01')
        self.iso.setBit(28, 'D00000250')
        self.iso.setBit(32, '98253709891')
        self.iso.setBit(33, '16253898789')
        self.iso.setBit(35, '4564712033207424')
        self.iso.setBit(37, self.retrieval_refrence_no)
        self.iso.setBit(41, 'CASHPOI')
        self.iso.setBit(42, 'CASHPOI' + self.atmid)
        self.iso.setBit(43, 'CASHPOINT ATM ,GIBBES STREET, SYDNEY')
        self.iso.setBit(47, 'TCC CODES')
        self.iso.setBit(48, '9865')
        self.iso.setBit(52, binascii.unhexlify('1234'))
        self.iso.setBit(53, '0000000000000001')
        self.iso.setBit(55, 'ICC DATA')
        self.iso.setBit(57, '000000010000')
        self.iso.setBit(64, 'MAC')

        try:
            message = self.iso.getNetworkISO()
            self.s.send(message)
            print 'Sending 200... %s' % message
            ans = self.s.recv(1024)
            print "Response  = %s" % ans
            isoAns = AS2805()
            isoAns.setNetworkISO(ans)
            v1 = isoAns.getBitsAndValues()
            for v in v1:
                print 'Bit %s of type %s with value = %s' % (v['bit'], v['type'], v['value'])

            if isoAns.getMTI() == '0210':
                if isoAns.getBit(39) == '00':
                    print "0200 Transaction Sucessfull"
                else:
                    print "0200 Transaction Failed"
            else:
                print "Could not process Transaction"

            self.s.close()
            return self.stan
        except InvalidAS2805, ii:
            print ii



    def SendReversal(self, stan):

        self.Connect()
       # Get esxisting bit values for processing
        self.iso.setMTI('0420')
        self.iso.setBit(11, stan)
        self.iso.setBit(37, self.retrieval_refrence_no)
        try:
            message = self.iso.getNetworkISO()
            self.s.send(message)
            print 'Sending 0420... %s' % message
            ans = self.s.recv(1024)
            print "Response  = %s" % ans
            isoAns = AS2805()
            isoAns.setNetworkISO(ans)
            v1 = isoAns.getBitsAndValues()
            for v in v1:
                print 'Bit %s of type %s with value = %s' % (v['bit'], v['type'], v['value'])

            if isoAns.getMTI() == '0430':
                if isoAns.getBit(39) == '00':
                    print "0420 Transaction Sucessfull"
                else:
                    print "0420 Transaction Failed"
            else:
                print "Could not process Transaction"

            self.s.close()

        except InvalidAS2805, ii:
            print ii


    def Alaric_KeyExchange(self):
        print "Alaric_KeyExchange()"
        self.Connect()
        d = datetime.now()
        iso = AS2805(debug=False)
        iso.setMTI('0820')
        iso.setBit(7, d.strftime("%m%d%H%M%S"))
        iso.setBit(11, self.stan)
        iso.setBit(12, d.strftime("%H%M%S"))
        iso.setBit(41, self.atmid)
        iso.setBit(13, d.strftime("%m%d"))
        iso.setBit(70, '101')

        try:
            message = iso.getNetworkISO()
            self.s.send(message)
            print 'Sending ... %s' % message
            ans = self.s.recv(1024)
            print "Response  = %s" % ans
            isoAns = AS2805()
            isoAns.setNetworkISO(ans)
            v1 = isoAns.getBitsAndValues()
            for v in v1:
                print 'Bit %s of type %s with value = %s' % (v['bit'], v['type'], v['value'])

            if isoAns.getMTI() == '0810':
                if isoAns.getBit(39) == '00':
                    print "0800 Key Exchange sucessful"
                else:
                    print "0800 Response Code = %s, Key Exchange Failed" % (isoAns.getBit(39),)
            else:
                print "Could not key exchange with 0800"
            self.s.close()
        except InvalidAS2805, ii:
            print ii


    def Process(self, atmid):
        self.atmid = atmid
        if self.Alaric_Login():
            self.Alaric_KeyExchange()
            for i in range(1000):
                rev_indicator = randint(1,200)
                if rev_indicator % 10 == 0:
                    self.SendReversal(self.stan)

        self.s.settimeout(20)
        print "timeout = %s" % (self.s.gettimeout())
        while True:
            try:
                ans = self.s.recv(2048)
                if ans == '':
                    self.s.close()
            except socket.error as e:
                print "%s, Noting Received, Error = %s" % (datetime.now(), e)
            time.sleep(10)



