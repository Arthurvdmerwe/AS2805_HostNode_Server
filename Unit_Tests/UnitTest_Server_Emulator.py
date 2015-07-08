import sys
from datetime import datetime
import struct

#print sys.path
import MySQLdb

from Data_Structures.AS2805_Structs.AS2805 import AS2805
from Data_Structures.AS2805_Structs.AS2805Errors import *
from Thales_HSM import KeyGenerator
from Shared.ByteUtils import ByteToHex
import Config


bigEndian = True


import socket


class ClientThread():

    def __init__(self,ip,port,clientsocket):
        #threading.Thread.__init__(self)
        self.con = MySQLdb.Connect(host=Config.switch_office_database_ip,port=Config.switch_office_database_port, db=Config.switch_office_database, user=Config.switch_office_database_user, passwd=Config.switch_office_database_pwd)
        cur = self.con.cursor(MySQLdb.cursors.DictCursor)
        self.ip = ip
        self.port = port
        self.socket = clientsocket
        print "[+] New thread started for " + ip + ":" + str(port)
        try:
            sql = "SELECT * FROM host_config WHERE host_name = 'CUSCAL' LIMIT 1"
            count = cur.execute(sql)
            print ("Records from sessions Table=%s" % (cur.rowcount,))

            if count == 1:
                row = cur.fetchone()
                self.KEKr = row['KEKr']
                self.KEKs = row['KEKs']
                self.KeyExchangeR = KeyGenerator.Generate_a_Set_of_Zone_Keys(KEKs=self.KEKs)

                self.ValidationRequest = KeyGenerator.Generate_KEKs_Validation_Request(KEKs=self.KEKs)
        finally:
            cur.close()

        #send Logon Request
        d = datetime.now()
        logon = AS2805(debug=False)
        logon.setMTI('0800')
        logon.setBit(7, d.strftime("%m%d%H%M%S"))
        logon.setBit(11, '230098')
        logon.setBit(33, '437586002')
        logon.setBit(48,  self.ValidationRequest["KRs"])
        logon.setBit(53, '0000000000000001')
        logon.setBit(70, '001')
        logon.setBit(100, '6100016')

        #print logon.dumpFields()
        ans = logon.getNetworkISO()
        print "SPS to SL:" +   ByteToHex(logon.getNetworkISO())

        self.socket.sendall(ans)

    def SendHostKeyExchange(self):
        #print self.KeyExchange
        print "ZAK Check Value" + self.KeyExchangeR["ZAK Check Value"]
        print "ZAK Check Value" + self.KeyExchangeR["ZAK Check Value"]
        print "ZPK Check Value" + self.KeyExchangeR["ZPK Check Value"]
        print "ZEK Check Value" + self.KeyExchangeR["ZEK Check Value"]
        #print self.ZoneKeySet1
        iso_req = AS2805(debug=False)
        d = datetime.now()
        iso_req.setMTI('0820')
        iso_req.setBit(7, d.strftime("%m%d%H%M%S"))
        iso_req.setBit(11, '111200')
        iso_req.setBit(33, '43758602')
        iso_req.setBit(48, self.KeyExchangeR["ZAK(ZMK)"][1:] + self.KeyExchangeR["ZPK(ZMK)"][1:])
        iso_req.setBit(53, '000000000000001')
        iso_req.setBit(70, '101')
        iso_req.setBit(100, '6100016')
        ans = iso_req.getNetworkISO()

        print "SPS to SL:" + ByteToHex(iso_req.getNetworkISO())
        self.socket.sendall(ans)

    def Send(self, pack):
        if bigEndian:
            ans = pack.getNetworkISO()
        else:
            ans = pack.getNetworkISO(False)

        print "SPS to SL:" + ByteToHex(pack.getNetworkISO())
        self.socket.sendall(ans)

    def run(self):
        print "Accepted connection from: ", self.ip
        while 1:

            length_indicator = self.socket.recv(2)
            if len(length_indicator) is not 2:
                break
            size = struct.unpack('!H', length_indicator)[0]
            payload = self.socket.recv(size)
            isoStr = payload
            if not isoStr:
                break
            else:
                pack = AS2805(debug=False)
                # parse the iso
                try:
                    if bigEndian:
                        pack.setNetworkISO(isoStr)
                    else:
                        pack.setNetworkISO(isoStr, False)

                    print "SL to SPS: " + ByteToHex(pack.getNetworkISO())

                    if pack.getMTI() == '0800':
                        if pack.getBit(70) == '0001':
                            ValidationResponse = KeyGenerator.Generate_KEKr_Validation_Response(KEKr=self.KEKr, KRs=ByteToHex(pack.getBit(48)))
                            pack.setMTI('0810')
                            pack.setBit(39, '00')
                            pack.setBit(48, ValidationResponse["KRr"])
                            self.Send(pack)
                            self.SendHostKeyExchange()
                        # Keep Alive
                        if pack.getBit(70) == '0301':
                            iso = AS2805()
                            iso.setMTI('0810')
                            iso.setBit(39, '00')
                            iso.setBit(33, '61100016')
                            iso.setBit(53, '0000000000000002')
                            iso.setBit(58, 'D98795000')
                            iso.setBit(59, 'C98795000')
                            iso.setBit(55, '8A0230309B025A31')
                            #pack.setBit(55, '8A023030')
                            self.socket.sendall(iso.getNetworkISO())
                    elif pack.getMTI() == '0810':
                        pass
                    elif pack.getMTI() == '0200':
                        pack.setMTI('0210')
                        pack.setBit(39, '00')

                        pack.setBit(33, '61100016')
                        pack.setBit(53, '0000000000000002')
                        pack.setBit(58, 'D98795000')
                        pack.setBit(59, 'C98795000')
                        pack.setBit(55, '8A0230309B025A31')
                        self.Send(pack)

                    elif pack.getMTI() == '0100':
                        pack.setMTI('0110')
                        pack.setBit(39, '00')
                        pack.setBit(55, '8A0230309B029100')
                        self.Send(pack)
                    elif pack.getMTI() == '0820':
                        if pack.getBit(70) == '0101':
                            KeyData = ByteToHex(pack.getBit(48))
                            #print "ZAK = " + KeyData[:32]
                            #print "ZPK = " + KeyData[32:]

                            KeyExchangeResponse = KeyGenerator.Translate_a_Set_of_Zone_Keys(KEKr=self.KEKr, ZPK=KeyData[32:], ZAK=KeyData[:32], ZEK='11111111111111111111111111111111')
                            pack.setMTI('0830')
                            pack.setBit(48, KeyExchangeResponse["ZAK Check Value"] + KeyExchangeResponse["ZPK Check Value"])
                            pack.setBit(39, '00')
                            self.Send(pack)


                    elif pack.getMTI() == '0830':

                        pass
                    elif pack.getMTI() == '0520':
                        pack.setMTI('0530')
                        pack.setBit(55, '8A0230309B029100')
                        pack.setBit(39, '00')
                        self.Send(pack)
                    elif pack.getMTI() == '0420':
                        pack.setMTI('0430')
                        pack.setBit(39, '00')
                        self.Send(pack)
                    elif pack.getMTI() == '0220':
                        pack.setMTI('0230')
                        pack.setBit(55, '8A0230309B029100')
                        pack.setBit(39, '00')
                        self.Send(pack)
                    else:
                        print "The client dosen't send the correct message!"
                        pass


                except InvalidAS2805, ii:
                    print ii
                    break
                except Exception as e:
                    print "Unexpected error: %s", sys.exc_info()[0]
                    print "Unexpected error: %s %s ", (e.message, e.args)
                    continue


host = '127.0.0.1'
port = 7000

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

tcpsock.bind((host,port))

tcpsock.listen(1)
print "\nListening for incoming connections..."
(clientsock, (ip, port)) = tcpsock.accept()
ClientThread(ip, port, clientsock).run()
