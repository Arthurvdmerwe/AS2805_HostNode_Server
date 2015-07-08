__author__ = 'arthurvandermerwe'
"http://ArthurVanDerMerwe.com"

import logging
import inspect
from datetime import timedelta, datetime

import time
import socket
import signal
import struct
import threading

import Config
from Shared.AS2805_Trace_Log import LogTrace
from Data_Structures.AS2805_Structs.AS2805 import ReadableAscii
from Data_Structures.AS2805_Structs.AS2805Errors import *
from Data_Structures.AS2805_Structs.AS2805DatabaseFieldMappings import *
from Data_Structures.AS2805_Structs.ASResponseCodes import GetISOResponseText
from Thales_HSM import KeyGenerator
from Shared import ByteUtils
from Shared.mySQLHandler import mySQLHandler
from Shared.AsyncCall import Async


class HostNode(threading.Thread):
    db_state = "closed"
    state = "new"
    s = None
    next_stan = 0
    stop = False


    def __init__(self, host_id, host_name):
        self.log = logging.getLogger(str(host_name))
        Async(self.log.debug("init()"))
        self.last_keep_alive = datetime.now()
        self.last_connect_SMS = datetime.now() - timedelta(minutes=10)
        self.stan_day = None
        self.host_name = host_name
        self.last_key_exchange = None
        self.node_number = '0'
        self.host_id = host_id
        self.SwitchLink_IIN = '0'
        self.HostIIN = '0'
        self.tran_0200_timeout = 0
        threading.Thread.__init__(self)

    def run(self):
        Async(self.log.info("Started"))
        try:
            while (not self.stop):
                Async(self.log.debug("Running, state = [%s]" %(self.state)))
                if self.db_state in ("closed"):
                    self.__dbConnect()
                    self.__getHostSettings()
                elif self.db_state in ("open"):
                    self.__getNextStan()
                elif self.db_state in ("ready"):
                    if self.state in ("new", "disconnected"):
                        self.__connect()
                    elif self.state in ("disconnect"):
                        self.__disconnect()
                    elif self.state in ("connect_fail"):
                        self.__connect_fail()
                    elif self.state in ("connected", "echo_failed", "signed_off"):
                        self.__signon__()
                    elif self.state in ("singon_failed"):
                        self.__signon_failed()
                    elif self.state in ("signed_on"):
                        self.__signon_dual__()
                    elif self.state in ("signed_on_dual"):
                        self.__keyExchange__()
                    elif self.state in ("key_exchange_failed"):
                        self.__setState("disconnect")
                    elif self.state in ("session_key_ok"):
                        Async(self.__sendRequests0200())
                        Async(self.__sendRequests0420())
                        #keeplive is sent by aquirer
                        #Async(self.__keepAlive())
                        Async(self.__getResponses())
                    elif self.state in ("blank_response"):
                        self.__disconnect()
                    else:
                        Async(self.log.error("Unknown state [%s]" % (self.state)))
                        break
                else:
                    Async(self.log.error("Unknown DB state [%s]" % (self.db_state)))
                    break
        except:
            Async(self.log.exception("Uncaught Exception in run() loop"))
        finally:
            Async(self.log.info("Run() Ended"))

    def __setState(self, state):
        Async(self.log.debug("state changed from [%s] -> [%s]" % (self.state, state)))
        self.state = state

    def __setDBState(self, state):
        Async(self.log.debug("db state changed from [%s] -> [%s]" % (self.db_state, state)))
        self.db_state = state

    def __getHostSettings(self):
        global cur
        Async(self.log.info("Getting Host Settings for %s ..." % self.host_name))
        try:
            cur = self.con_switch_office.cursor(MySQLdb.cursors.DictCursor)
            sql = 'SELECT host_name, host_iin, sl_iin, host_ip, host_port, host_timeout, 0200_timeout, KEKr, KEKs FROM host_config where id = %s' % (self.host_id)
            cur.execute(sql)
            row = cur.fetchone()

            self.HostIIN = row['host_iin']
            self.SwitchLink_IIN = row['sl_iin']
            self.KEKr = row['KEKr']
            self.KEKs = row['KEKs']
            self.host = row['host_ip']
            self.port = int(row['host_port'])
            self.tran_0200_timeout = int(row['0200_timeout'])

            Async(self.log.info("Host Settings Assigned..."))
        finally:
            cur.close()

    def __dbConnect(self):
        try:
            Async(self.log.info("Connecting to Switch Database..."))
            self.con_switch = MySQLdb.Connect(
                host=Config.switch_database_ip,
                port=Config.switch_database_port,
                db=Config.switch_database_database,
                user=Config.switch_database_user,
                passwd=Config.switch_database_pwd)


            Async(self.log.info("Connecting to Config Database..."))

            self.con_switch_office = MySQLdb.Connect(
                host=Config.switch_office_database_ip,
                port=Config.switch_office_database_port,
                db=Config.switch_office_database,
                user=Config.switch_office_database_user,
                passwd=Config.switch_office_database_pwd)
            self.__setDBState("open")
        except:
            Async(self.log.exception("Connecting to database"))

    def __getNextStan(self):
        """
        Gets the maximum System Trace Audit Number for the current date.
        The STAN will continue to increment as long as the node is running.
        """
        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        Async(self.log.debug("Function Start: %s" % inspect.stack()[0][3]))
        if self.stan_day is None:
            # We have not yet gotten the maximum stan from the database
            Async(self.log.info("Getting latest STAN for today from database"))
            try:
                self.stan_day = "%s" % (datetime.today().strftime("%m%d"))
                cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
                sql = """
                    SELECT IFNULL(MAX(p11_stan+0), 0) AS LastStan
                    FROM host_cuscal
                    WHERE p13_date_local_tran = '%s'
                    """ % (self.stan_day, )
                cur.execute(sql)
                Async(self.log.debug("Records=%s" % (cur.rowcount,)))

                row = cur.fetchone()
                self.next_stan = row['LastStan'] + 1
                Async(self.log.debug("Next STAN = %d" % self.next_stan))
                self.__setDBState("ready")
            finally:
                self.con_switch.commit()
                cur.close()
        else:
            # Start stan at 1 if the day has changed
            if datetime.today().strftime("%m%d") != self.stan_day:
                Async(self.log.debug("Its a new day, reset the STAN"))
                self.next_stan = 1
                self.stan_day = "%s" % (datetime.today().strftime("%m%d"))
            else:
                self.next_stan += 1

        formatted_stan = ("000000%d" % self.next_stan)[-6:]
        Async(self.log.debug("stan = %s" % formatted_stan))
        return formatted_stan

    def __connect(self):
        Async(self.log.debug("__connect()"))
        d = datetime.now()
        if self.last_connect_SMS + timedelta(minutes=5) < d:
            self.last_connect_SMS = d

            try:
                self.__setState("connecting %s on %s:%d" %(self.host_name, self.host, self.port))
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.settimeout(10.0)
                self.s.connect((self.host, self.port))
                self.__setState("connected")

            except socket.error as err:
                Async(self.log.error("could not connect to %s [%s] on IP: %s and Port %s " % (self.host_name, err, self.host, self.port)))
                self.s = None
                self.__setState("connect_fail")

    def __connect_fail(self):
        Async(self.log.debug("__connect_fail()"))
        Async(self.log.critical("Sleeping for 30 Seconds before connecting again"))
        try:
            time.sleep(30)
            self.__setState("disconnected")
        except:
            Async(self.log.error("Error while sleeping"))
            self.__setState("terminate")

    def __disconnect(self):
        Async(self.log.debug("__disconnect()"))
        try:
            self.__setState("disconnecting")
            self.s.close()
            self.__setState("disconnected")
            time.sleep(10)
        except socket.error as err:
            Async(self.log.error("error disconnecting [%s]" % (err)))
            self.s = None
            self.__setState("disconnected")

    def __signon__REQ(self, iso):

        self.__setState('signing_on')
        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)

        try:

                payload = iso
                d = datetime.now()
                Async(self.log.info(" Getting Sign-On Request 0800 =  [%s]" %  ByteUtils.ByteToHex(payload)))
                if payload == '':
                    Async(self.log.critical('Received a blank response from switch... might be a disconnect'))
                    self.__setState("blank_response")
                else:
                    iso_ans = AS2805(debug=False)
                    iso_ans.setNetworkISO(payload)

                    trace_sql = LogTrace(iso_ans, self.host_id,  iso_ans.getMTI(), '')
                    Async(cur.execute(trace_sql))



                    #self.__storeISOMessage(iso_ans, {"date_time_received": d.strftime("%Y-%m-%d %H:%M:%S")})
                    if iso_ans.getMTI() == '0800':
                        if iso_ans.getBit(70) == '001':
                            sql = "SELECT * FROM sessions_as2805 WHERE host_id = '%s' and keyset_description = 'Recieve' LIMIT 1" % self.host_id
                            count = cur.execute(sql)
                            Async(self.log.debug("Records=%s" % (cur.rowcount,)))

                            if count == 1:
                                row = cur.fetchone()
                                self.KEKr = row['KEKr']
                                self.KEKs = row['KEKs']
                                log.info("Logon Started with KEKr = %s, KEKs = %s" % ( self.KEKr, self.KEKs))
                                KRs = iso_ans.getBit(48)
                                log.info("KRs %s Received from Host" % (KRs))

                                self.ValidationResponse = KeyGenerator.Generate_KEKr_Validation_Response(KEKr=self.KEKr, KRs=KRs)


                                if self.ValidationResponse["ErrorCode"] == '00':
                                    log.info("KRs Validation Response %s generated" % (self.ValidationResponse["KRr"]))
                                    d = datetime.now()
                                    iso_resp = AS2805(debug=False)
                                    iso_resp.setMTI('0810')
                                    iso_resp.setBit(7, d.strftime("%m%d%H%M%S"))
                                    iso_resp.setBit(11, iso_ans.getBit(11))
                                    iso_resp.setBit(33, self.SwitchLink_IIN)
                                    iso_resp.setBit(39, '00')
                                    iso_resp.setBit(48, self.ValidationResponse["KRr"])
                                    iso_resp.setBit(70, '001')
                                    iso_resp.setBit(100, self.SwitchLink_IIN)
                                    iso_send = iso_resp.getNetworkISO()

                                    trace_sql = LogTrace(iso_resp, self.host_id, iso_resp.getMTI(), iso_resp.getBit(39))
                                    Async(cur.execute(trace_sql))

                                    Async(self.log.info("Sending Sign-On Response 0810 [%s]" % ReadableAscii(iso_send)))
                                    self.s.send(iso_send)
                                    Async(self.__storeISOMessage(iso_resp, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S")}))
                                    self.__setState('signed_on')
                                else:
                                    Async(self.log.error("0810 KRr Response Code = %s, Login Failed" % (self.ValidationResponse["ErrorCode"],)))
                                    #TODO: Send Decline to the Partner
                            else:
                                Async(self.log.error("Could not login with 0800"))
                        else:
                            Async(self.log.error("Could not login with 0810"))

        except InvalidAS2805, ii:
            Async(self.log.error(ii))
        except socket.error as e:
            pass
            Async(self.log.debug("nothing from host [%s]" % (e)))
        except:
            #self.__signoff()
            Async(self.log.exception("signon_failed"))
            self.__setState("singon_failed")
        finally:
            self.con_switch.commit()
            cur.close()

    def __signon__(self):
        Async(self.log.info("====Sign-On Process Started ===="))
        self.__setState('signing_on')
        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)


        try:
            Async(self.log.info("Waiting for 0800 Request"))
            self.s.settimeout(20.0)
            length_indicator = self.s.recv(2)
            if length_indicator == '':
                Async(self.log.critical('Received a blank length indicator from switch... might be a disconnect'))
                self.__setState("blank_response")
            else:
                size = struct.unpack('!H', length_indicator)[0]
                payload = self.s.recv(size)

                Async(self.log.info(" Getting Sign-On Request 0800 =  [%s]" % ByteUtils.ByteToHex(payload)))
                if payload == '':
                    Async(self.log.critical('Received a blank response from switch... might be a disconnect'))
                    self.__setState("blank_response")
                else:
                    iso_ans = AS2805(debug=False)
                    iso_ans.setNetworkISO(payload)

                    trace_sql = LogTrace(iso_ans, self.host_id, iso_ans.getMTI(), '')
                    Async(cur.execute(trace_sql))

                    Async(self.__storeISOMessage(iso_ans, {"date_time_received": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
                    if iso_ans.getMTI() == '0800':
                        if iso_ans.getBit(70) == '0001':
                            #log.info("Logon Started with KEKr = %s, KEKs = %s" % ( self.KEKr, self.KEKs))
                            KRs = ByteUtils.ByteToHex(iso_ans.getBit(48))
                            #log.info("KRs %s Received from Host" % (KRs))
                            #print "Generating a E0 Command with KEKr=%s, and KRs=%s" % (self.KEKr, KRs)
                            self.ValidationResponse = KeyGenerator.Generate_KEKr_Validation_Response(KEKr=self.KEKr, KRs=KRs)
                            #print self.ValidationResponse

                            if self.ValidationResponse["ErrorCode"] == '00':
                                #log.info("KRs Validation Response %s generated" % (self.ValidationResponse["KRr"]))
                                d = datetime.now()
                                iso_resp = AS2805(debug=False)
                                iso_resp.setMTI('0810')
                                iso_resp.setBit(7, d.strftime("%m%d%H%M%S"))
                                iso_resp.setBit(11, iso_ans.getBit(11))
                                iso_resp.setBit(33, self.SwitchLink_IIN)
                                iso_resp.setBit(39, '00')
                                iso_resp.setBit(48, self.ValidationResponse["KRr"])
                                iso_resp.setBit(70, '0001')
                                iso_resp.setBit(100, self.SwitchLink_IIN)

                                iso_send = iso_resp.getNetworkISO()

                                trace_sql = LogTrace(iso_resp, self.host_id, iso_resp.getMTI(), iso_resp.getBit(39))
                                Async(cur.execute(trace_sql))


                                Async(self.log.info("Sending Sign-On Response 0810 [%s]" % ByteUtils.ByteToHex(iso_send)))
                                self.s.send(iso_send)
                                Async(self.__storeISOMessage(iso_resp, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
                                self.__setState('signed_on')
                            else:
                                Async(self.log.error("0810 KRr Response Code = %s, Login Failed" % (self.ValidationResponse["ErrorCode"],)))
                                #TODO: Send Decline to the Partner

                        else:
                            Async(self.log.error("Could not login with 0810"))



        except InvalidAS2805, ii:
            Async(self.log.error(ii))
        except socket.error as e:
            pass
            Async(self.log.debug("nothing from host [%s]" % (e)))
        except:
            #self.__signoff()
            Async(self.log.exception("signon_failed"))
            self.__setState("singon_failed")
        finally:
            self.con_switch.commit()
            cur.close()

    def __signon_dual__(self):
        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        try:
            self.s.settimeout(20.0)
            self.ValidationRequest = KeyGenerator.Generate_KEKs_Validation_Request(KEKs=self.KEKs)
            d = datetime.now()
            iso_resp = AS2805(debug=False)
            iso_resp.setMTI('0800')
            iso_resp.setBit(7, d.strftime("%m%d%H%M%S"))
            iso_resp.setBit(11, self.__getNextStan())
            iso_resp.setBit(33, self.HostIIN)
            iso_resp.setBit(48, self.ValidationRequest["KRs"])
            iso_resp.setBit(70, '001')
            iso_resp.setBit(100, self.HostIIN)
            iso_send = iso_resp.getNetworkISO()

            trace_sql = LogTrace(iso_resp, self.host_id, iso_resp.getMTI(), '')
            Async(cur.execute(trace_sql))


            Async(self.log.info("Sending Sign-On Request 0800 [%s]" % ByteUtils.ByteToHex(iso_send)))
            self.s.send(iso_send)
            Async(self.__storeISOMessage(iso_resp, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))

            Async(self.log.info("Waiting for 0810 Response"))

            length_indicator = self.s.recv(2)
            size = struct.unpack('!H', length_indicator)[0]
            payload = self.s.recv(size)

            Async(self.log.info(" Getting Sign-On Response 0810 =  [%s]" % ByteUtils.ByteToHex(payload)))
            iso_ans = AS2805(debug=False)
            iso_ans.setNetworkISO(payload)

            trace_sql = LogTrace(iso_ans, self.host_id, iso_ans.getMTI(), iso_ans.getBit(39))
            Async(cur.execute(trace_sql))



            Async(self.log.debug(iso_ans.dumpFields()))
            Async(self.__storeISOMessage(iso_ans, {"date_time_received": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
            if iso_ans.getBit(39) == '00':
                Async(self.log.info("====Sign-On Sequence Completed Successfully===="))
                self.__setState("signed_on_dual")
            else:
                #self.__signoff()
                Async(self.log.error("Could not login with 0800"))
                self.__setState("singon_failed")
        except InvalidAS2805, ii:
            Async(self.log.info(ii))
        except socket.error as e:
            Async(self.log.info("nothing from host [%s]" % (e)))
        except:
            #self.__signoff()
            Async(self.log.exception("signon_failed"))
            self.__setState("singon_failed")
        finally:
            self.con_switch.commit()
            cur.close()

    def __signoff(self):
            self.__setState('signing_off')
            d = datetime.now()
            iso_req = AS2805(debug=False)
            iso_req.setMTI('0820')
            iso_req.setBit(7, d.strftime("%m%d%H%M%S"))
            iso_req.setBit(11, self.__getNextStan())
            iso_req.setBit(33, self.HostIIN)
            iso_req.setBit(70, '0002')
            iso_req.setBit(100, self.SwitchLink_IIN)
            Async(self.__storeISOMessage(iso_req, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
            try:

                iso_send = iso_req.getNetworkISO()

                Async(self.log.debug(iso_req.dumpFields()))
                Async(self.log.info("Sending Sign-Off Request [%s]" % ReadableAscii(iso_send)))
                self.s.send(iso_send)
                Async(self.log.debug("Waiting for Response"))
                self.s.settimeout(10.0)
                payload = self.s.recv(8192)

                Async(self.log.info("Sign-Off Response =      [%s]" % ReadableAscii(payload)))
                iso_ans = AS2805()
                iso_ans.setIsoContent(payload)
                Async(self.log.debug(iso_ans.dumpFields()))

                Async(self.__storeISOMessage(iso_ans, {"date_time_received": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
                # TODO: Make the sign-on asynchronous
                if iso_ans.getMTI() == '0830':
                    if iso_ans.getBit(39) == '0303':
                        Async(self.log.info("0800 Logoff successful"))
                        self.__setState("signed_off")
                    else:
                        Async(self.log.error("0800 Response Code = %s, Sign Off Failed" % (iso_ans.getBit(39),)))
                else:
                    Async(self.log.error("Could not logoff with 0800"))

            except InvalidAS2805, ii:
                Async(self.log.error(ii))
            except:
                Async(self.log.exception("signoff_failed"))
                self.__setState("singoff_failed")

    def __signon_failed(self):
        Async(self.log.debug("__signon_failed()"))
        Async(self.log.critical("Sleeping for 30 Seconds before connecting again"))
        try:
            time.sleep(30)
            self.__setState("disconnect")
        except:
            Async(self.log.error("Error while sleeping"))
            self.__setState("terminate")

    def __keyExchange__(self):
        self.__setState("key_exchange")

        self.__key_exchange_listen()


        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        d = datetime.now()
        self.ZoneKeySet1 = {}
        self.ZoneKeySet2 = {}
        self.ZoneKeySet1 = KeyGenerator.Generate_a_Set_of_Zone_Keys(self.KEKs)


        iso_req = AS2805(debug=False)
        iso_req.setMTI('0820')
        iso_req.setBit(7, d.strftime("%m%d%H%M%S"))
        iso_req.setBit(11, self.__getNextStan())
        iso_req.setBit(33, self.HostIIN)
        iso_req.setBit(48, self.ZoneKeySet1["ZAK(ZMK)"][1:] + self.ZoneKeySet1["ZPK(ZMK)"][1:])
        iso_req.setBit(53, self.node_number)
        iso_req.setBit(70, '101')
        iso_req.setBit(100, self.SwitchLink_IIN)
        Async(self.__storeISOMessage(iso_req, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
        log.info("Send Keys under LMK : ZAK= %s, ZAK Check Value: %s ZPK = %s, ZPK Check Value: %s" % (self.ZoneKeySet1["ZAK(LMK)"], self.ZoneKeySet1["ZAK Check Value"],  self.ZoneKeySet1["ZPK(LMK)"], self.ZoneKeySet1["ZPK Check Value"]))

        try:

            # send the Send Keys
            iso_send = iso_req.getNetworkISO()

            trace_sql = LogTrace(iso_req, self.host_id, iso_req.getMTI(), '')
            Async(cur.execute(trace_sql))


            Async(self.log.debug(iso_req.dumpFields()))
            Async(self.log.info("Sending Key Exchange Request  = [%s]" % ByteUtils.ByteToHex(iso_send)))
            self.s.send(iso_send)

            self.s.settimeout(20.0)
            length_indicator = self.s.recv(2)
            if length_indicator == '':
                Async(self.log.critical('Received a blank length indicator from switch... might be a disconnect'))
                self.__setState("blank_response")
            else:
                size = struct.unpack('!H', length_indicator)[0]
                payload = self.s.recv(size)
                payload = ByteUtils.ByteToHex(payload)
                d = datetime.now()
                Async(self.log.info(" Receiving Key Exchange Response =  [%s]" % payload))
                if payload == '':
                    Async(self.log.critical('Received a blank response from switch... might be a disconnect'))
                    self.__setState("blank_response")
                else:
                    iso_ans = AS2805(debug=False)
                    iso_ans.setIsoContent(payload)

                    trace_sql = LogTrace(iso_ans, self.host_id, iso_ans.getMTI(), iso_ans.getBit(39))
                    Async(cur.execute(trace_sql))

                    Async(self.log.debug(iso_ans.dumpFields()))
                    Async(self.__storeISOMessage(iso_ans, {"date_time_received": d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))

                    if iso_ans.getMTI() == '0830':
                        if iso_ans.getBit(39) == '00':

                            Value = ByteUtils.ByteToHex(iso_ans.getBit(48))
                            self.KMACs_KVC = Value[:6]
                            self.KPEs_KVC = Value[6:]
                            Async(self.log.info("KMACs_KVC = %s, KPEs_KVC = %s" % (self.KMACs_KVC, self.KPEs_KVC)))
                            if self.KMACs_KVC == self.ZoneKeySet1["ZAK Check Value"] and self.KPEs_KVC == self.ZoneKeySet1["ZPK Check Value"]:
                                Async(self.log.info("0820 Key Exchange successful: Check Values Match, ZAK Check Value= %s , ZPK Check Value = %s" % (self.ZoneKeySet1["ZAK Check Value"], self.ZoneKeySet1["ZPK Check Value"])))
                                sql = """UPDATE sessions_as2805
                                          SET
                                          ZPK_LMK = '%s',
                                          ZPK_ZMK = '%s',
                                          ZPK_Check= '%s' ,
                                          ZAK_LMK= '%s',
                                          ZAK_ZMK = '%s',
                                          ZAK_Check ='%s',
                                          ZEK_LMK = '%s' ,
                                          ZEK_ZMK = '%s',
                                          ZEK_Check = '%s',
                                          keyset_number = '%s'
                                          WHERE host_id = '%s' and keyset_description = 'Send' """%\
                                         (  self.ZoneKeySet1["ZPK(LMK)"],
                                            self.ZoneKeySet1["ZPK(ZMK)"],
                                            self.ZoneKeySet1["ZPK Check Value"],
                                            self.ZoneKeySet1["ZAK(LMK)"],
                                            self.ZoneKeySet1["ZAK(ZMK)"],
                                            self.ZoneKeySet1["ZAK Check Value"],
                                            self.ZoneKeySet1["ZEK(LMK)"],
                                            self.ZoneKeySet1["ZEK(ZMK)"],
                                            self.ZoneKeySet1["ZEK Check Value"],
                                            self.node_number,
                                            self.host_id)

                                cur.execute(sql)
                                Async(self.log.debug("Records=%s" % (cur.rowcount,)))
                                self.__setState("key_exchanged")

                                self.__setState('session_key_ok')
                                Async(self.log.info("==== Key Exchange Sequence Completed Successfully===="))
                                Async(self.log.info("....WAITING FOR TRANSACTIONS....."))
                                self.last_key_exchange = datetime.now()

                            else:
                                Async(self.log.error("Generate_a_Set_of_Zone_Keys: KVC Check Failed!!"))
                        else:
                            Async(self.log.error("0820 Response Code = %s, Key Exchange Failed" % (iso_ans.getBit(39))))
        except InvalidAS2805, ii:
            Async(self.log.error(ii))
            self.s.close()
            self.s = None
            self.__setState("session_key_fail")
        except:
            Async(self.log.exception("key_exchange_failed"))
            self.__setState('key_exchange_failed')
        finally:
            self.con_switch.commit()

    def __key_exchange_listen(self):

        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        Async(self.log.info("===== Key Exchange process Started ======="))
        self.s.settimeout(20.0)
        length_indicator = self.s.recv(2)
        if length_indicator == '':
            Async(self.log.critical('Received a blank length indicator from switch... might be a disconnect'))
            self.__setState("blank_response")
        else:
            size = struct.unpack('!H', length_indicator)[0]
            payload = self.s.recv(size)

            Async(self.log.info(" Receiving Key Exchange Request =  [%s]" % ByteUtils.ByteToHex(payload)))
            if payload == '':
                Async(self.log.critical('Received a blank response from switch... might be a disconnect'))
                self.__setState("blank_response")
            else:
                iso_ans = AS2805(debug=False)
                iso_ans.setNetworkISO(payload)

                trace_sql = LogTrace(iso_ans, self.host_id, iso_ans.getMTI(), '')
                Async(cur.execute(trace_sql))

                Async(self.log.debug(iso_ans.dumpFields()))

                Async(self.__storeISOMessage(iso_ans, {"date_time_received": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
                if iso_ans.getMTI() == '0820' and iso_ans.getBit(70) == '0101':
                    Value = ByteUtils.ByteToHex(iso_ans.getBit(48))
                    self.ZAK = Value[:32]
                    self.ZPK = Value[32:]

                    self.node_number = iso_ans.getBit(53)
                    Async(self.log.info("Recieve Keys under ZMK : ZAK= %s, ZPK = %s" % (self.ZAK, self.ZPK )))

                    self.ZoneKeySet2 = KeyGenerator.Translate_a_Set_of_Zone_Keys(self.KEKr,ZPK=self.ZPK, ZAK=self.ZAK, ZEK='11111111111111111111111111111111')
                    cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
                    sql = """UPDATE sessions_as2805 set
                                    ZPK_LMK = '%s',
                                    ZPK_ZMK = '%s',
                                    ZPK_Check ='%s',
                                    ZAK_LMK = '%s' ,
                                    ZAK_ZMK = '%s',
                                    ZAK_Check = '%s',
                                    ZEK_LMK = '%s',
                                    ZEK_Check = '%s',
                                    keyset_number = '%s'
                                      WHERE host_id = '%s' and keyset_description = 'Recieve' """ %\
                                (
                                self.ZoneKeySet2["ZPK(LMK)"],
                                self.ZPK,
                                self.ZoneKeySet2["ZPK Check Value"],
                                self.ZoneKeySet2["ZAK(LMK)"],
                                self.ZAK,
                                self.ZoneKeySet2["ZAK Check Value"],
                                self.ZoneKeySet2["ZEK(LMK)"],
                                self.ZoneKeySet2["ZEK Check Value"],
                                self.node_number,
                                self.host_id)
                    Async(self.log.info("Recieve Keys under LMK : ZAK= %s, ZAK Check Value: %s ZPK = %s, ZPK Check Value: %s" % (self.ZoneKeySet2["ZAK(LMK)"], self.ZoneKeySet2["ZAK Check Value"],  self.ZoneKeySet2["ZPK(LMK)"], self.ZoneKeySet2["ZPK Check Value"])))
                    cur.execute(sql)
                    Async(self.log.debug("Records=%s" % (cur.rowcount,)))
                    iso_req = AS2805(debug=False)
                    iso_req.setMTI('0830')
                    iso_req.setBit(7, iso_ans.getBit(7))
                    iso_req.setBit(11, iso_ans.getBit(11))
                    iso_req.setBit(33, iso_ans.getBit(33))
                    iso_req.setBit(39, '00')
                    iso_req.setBit(48, self.ZoneKeySet2["ZAK Check Value"] + self.ZoneKeySet2["ZPK Check Value"])
                    iso_req.setBit(53,  iso_ans.getBit(53))
                    iso_req.setBit(70, iso_ans.getBit(70))
                    iso_req.setBit(100, iso_ans.getBit(100))
                    try:

                        iso_send = iso_req.getNetworkISO()
                        trace_sql = LogTrace(iso_req, self.host_id, iso_req.getMTI(), iso_req.getBit(39))
                        Async(cur.execute(trace_sql))

                        Async(self.log.debug(iso_req.dumpFields()))
                        Async(self.log.info("Sending  Key Exchange Response  = [%s]" % ByteUtils.ByteToHex(iso_send)))
                        self.s.send(iso_send)
                        self.node_number = iso_ans.getBit(53)
                    except:
                        Async(self.log.exception("key_exchange_failed"))
                        self.__setState('key_exchange_failed')

                    finally:
                        self.con_switch.commit()
                        cur.close()

    def __keepAlive(self):

        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        d = datetime.now()
        if self.last_keep_alive + timedelta(minutes=3) < d:
            self.last_keep_alive = d
            iso_req = AS2805(debug=False)
            iso_req.setMTI('0800')
            iso_req.setBit(7, d.strftime("%m%d%H%M%S"))
            iso_req.setBit(11, self.__getNextStan())
            iso_req.setBit(33, self.SwitchLink_IIN)
            iso_req.setBit(13, d.strftime("%m%d"))
            iso_req.setBit(70, '301')
            iso_req.setBit(100, self.HostIIN)
            Async(self.__storeISOMessage(iso_req, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S"), "dt_processed" : d.strftime("%Y-%m-%d %H:%M:%S"), "host_id":  self.host_id }))
            try:
                iso_send = iso_req.getNetworkISO()

                trace_sql = LogTrace(iso_req, self.host_id, iso_req.getMTI(), '' )
                Async(cur.execute(trace_sql))

                Async(self.log.debug(iso_req.dumpFields()))
                Async(self.log.info("Sending Echo Request [%s]" % ByteUtils.ByteToHex(iso_send)))
                self.s.send(iso_send)


                #Async(self.log.info("Waiting for Response")
                try:
                    self.s.settimeout(10.0)
                    length_indicator = self.s.recv(2)
                    size = struct.unpack('!H', length_indicator)[0]
                    payload = self.s.recv(size)
                except:
                    Async(self.log.exception("timeout"))
                    self.__setState("echo_failed")
                else:
                    Async(self.log.info("Echo Response        [%s]" % ByteUtils.ByteToHex(payload)))
                    iso_ans = AS2805()
                    iso_ans.setNetworkISO(payload)

                    trace_sql = LogTrace(iso_ans, self.host_id, iso_ans.getMTI(), iso_ans.getBit(39))
                    Async(cur.execute(trace_sql))

                    Async(self.log.debug(iso_ans.dumpFields()))

                    if iso_ans.getMTI() == '0810':
                        if iso_ans.getBit(39) == '00':
                            Async(self.log.info("0800 Echo successful"))
                        else:
                            Async(self.log.error("0800 Response Code = %s, Echo Failed" % (iso_ans.getBit(39),)))
                            self.__setState("echo_failed")
                    else:
                        Async(self.log.error("Could not echo with 0800"))
                        self.__setState("disconnected")

            except InvalidAS2805, ii:
                Async(self.log.error(ii))
            finally:
                self.con_switch.commit()
                cur.close()

    def __keepAlive_REQ(self, iso_req):

        d = datetime.now()
        self.last_keep_alive = d
        Async(self.log.info("Echo Request Recieved [%s]" % ReadableAscii(iso_req.getNetworkISO())))
        Async(self.log.debug(iso_req.dumpFields()))

        d = datetime.now()
        iso_resp = AS2805(debug=False)
        iso_resp.setMTI('0810')
        iso_resp.setBit(7, iso_req.getBit(7))
        iso_resp.setBit(11, iso_req.getBit(11))
        iso_resp.setBit(33, iso_req.getBit(33))
        iso_resp.setBit(39, '00')
        iso_resp.setBit(70, '0301')
        iso_resp.setBit(100, iso_req.getBit(100))

        Async(self.__storeISOMessage(iso_resp, {"date_time_sent": d.strftime("%Y-%m-%d %H:%M:%S"), "dt_processed" : d.strftime("%Y-%m-%d %H:%M:%S")}))
        try:
            iso_send = iso_resp.getNetworkISO()
            Async(self.log.debug(iso_req.dumpFields()))
            Async(self.log.info("Sending Echo Response Sent[%s]" % ReadableAscii(iso_send)))
            self.s.send(iso_send)

        except InvalidAS2805, ii:
            Async(self.log.error(ii))



    def __sendRequests0200(self):

        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        try:
            #TODO: Insert host id here
            sql = """ SELECT *  FROM host_cuscal WHERE message = '0200' AND p11_stan IS NULL AND date_time_sent IS NULL AND dt_processed IS NULL AND host_id = '%s' LIMIT 1 """ % (self.host_id)
            count = cur.execute(sql)
            if count == 1:
                row = cur.fetchone()
                Async(self.log.info( "%s Unsent Record Found  : auto_id=[%s], message=[%s]" % (count, row['auto_id'], row['message'])))

                # 0200 Records that are old (timeout) should not be sent
                if row["dt_created"] < datetime.now() - timedelta(seconds=self.tran_0200_timeout):
                    Async(self.log.critical("0200 to old to send : auto_id=[%s], tran_gid=[%s]" % (row['auto_id'], row['tran_gid'])))
                    sql = """ UPDATE host_cuscal SET dt_processed = NOW(), process_result = "0200 to old to send" WHERE auto_id = %s  """ % (row['auto_id'])
                    to_old = cur.execute(sql)
                    Async(self.log.info("0200 to old to send : auto_id=[%s], tran_gid=[%s] updated [%s] records" % ( row['auto_id'], row['tran_gid'], to_old)))
                else:
                    p11_stan = self.__getNextStan()
                    d = datetime.now()
                    p7_transmit_dt = d.strftime("%m%d%H%M%S")

                    sql = """ UPDATE host_cuscal SET p11_stan = '%s', p7_transmit_dt = '%s', date_time_sent = '%s' WHERE auto_id = %s """ % (p11_stan, p7_transmit_dt, d.strftime("%Y%m%d%H%M%S"), row['auto_id'])
                    count = cur.execute(sql)
                    Async(self.log.info("%s 0200 records flagged as sent: auto_id=[%s], tran_gid=[%s]" % ( count, row['auto_id'], row['tran_gid'])))
                    try:

                        iso_req = AS2805(debug=False)
                        iso_req = Get_AS_from_Database_Table(cur, row['tran_gid'], '0200')
                        iso_req.setBit(7, p7_transmit_dt)
                        iso_req.setBit(11, p11_stan)
                        iso_req.setBit(32, self.SwitchLink_IIN)
                        iso_req.setBit(42, self.SwitchLink_IIN)
                        iso_req.setBit(53, self.node_number)
                        #MacResult = KeyGenerator.CalculateMAC_ZAK(iso_req.getNetworkISO()[2:].upper(), row['p64_mac'])

                        #TESTING
                        MacResult = {}
                        MacResult["MAC"] = "65432123"
                        iso_req.setBit(64, MacResult["MAC"] + '00000000')
                        Async(self.log.debug(iso_req.dumpFields()))
                        iso_send = iso_req.getNetworkISO()
                        Async(self.log.info("Sending 0200 Request  [%s]" % ByteUtils.ByteToHex(iso_send)))
                        self.s.send(iso_send)

                        trace_sql = LogTrace(iso_req, self.host_id, iso_req.getMTI(), '')
                        Async(cur.execute(trace_sql))

                    except Exception as e:
                        Async(self.log.exception("Exception in sending a 0200 request with message '%s" % e.message))
        finally:
            self.con_switch.commit()
            cur.close()

    def __sendRequests0420(self):

        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        try:
                row = self.__GetRecord(cur, '0420')
                if row is not None:

                    iso_req = Get_AS_from_Database_Table(cur, row['tran_gid'], '0420')
                    Async(self.log.debug(iso_req.dumpFields()))
                    iso_send = iso_req.getNetworkISO()

                    Async(self.log.debug("Sending Request [%s]" % ReadableAscii(iso_send)))
                    self.s.send(iso_send)
        finally:
            cur.close()

    def __GetRecord(self, cur, message):
        sql = """
                SELECT *
                FROM host_cuscal
                WHERE message = '%s'
                  AND date_time_sent IS NULL
                LIMIT 1
                """ % message
        count = cur.execute(sql)
        if count == 1:
            row = cur.fetchone()
            Async(self.log.info( "%s Unsent Record Found  : auto_id=[%s], message=[%s]" % (count, row['auto_id'], row['message'])))
            # TODO: 0420 Records that are old (timeout) should not be sent

            p11_stan = self.__getNextStan()
            d = datetime.now()
            p7_transmit_dt = d.strftime("%m%d%H%M%S")
            sql = """
                UPDATE host_cuscal
                SET
                p11_stan = '%s',
                p7_transmit_dt = '%s',
               date_time_sent = '%s'
                WHERE
                auto_id = %s
                """ % (p11_stan,
                       p7_transmit_dt,
                       d.strftime("%Y%m%d%H%M%S"),
                       row['auto_id'])

            Async(cur.execute(sql))
            Async(self.log.info("Unsent Record Updated: auto_id=[%s], message=[%s]" % (row['auto_id'], row['message'])))
            return row




    def __getResponses(self):
        cur = con.cursor(MySQLdb.cursors.DictCursor)
        try:

            #Async(self.log.debug("Waiting for Response")
            self.s.settimeout(1.0)
            length_indicator = self.s.recv(2)
            if length_indicator == '':
                Async(self.log.critical('Received a blank length indicator from switch... might be a disconnect'))
                self.__setState("blank_response")
            else:
                size = struct.unpack('!h', length_indicator)[0]
                Async(self.log.debug("Response Length  = [%s] = [%s]" % (ReadableAscii(length_indicator), size)))
                payload = self.s.recv(size)
                payload = ByteUtils.ByteToHex(payload)
                d = datetime.now()
                Async(self.log.info("Response Received Payload = [%s]" % ReadableAscii(payload)))
                if payload == '':
                    Async(self.log.critical('Received a blank response from switch... might be a disconnect'))
                    self.__setState("blank_response")
                else:

                    try:
                        iso_ans = AS2805(debug=False)
                        iso_ans.setIsoContent(payload)


                        #Async(self.log.info("Response Payload = [%s]" % ReadableAscii(payload))
                        Async(self.log.debug(iso_ans.dumpFields()))
                        #Async(self.log.info("Received =[%s] with Bit 70 = [%s]" % (iso_ans.getMTI(), iso_ans.getBit(70)))
                        if iso_ans.getMTI() == "0210":
                            Async(self.log.info('0210 Financial Response Received [%s]' % iso_ans.getBit(39)))

                        elif iso_ans.getMTI() == "0430":
                            Async(self.log.info('Reversal Response Received'))
                        elif iso_ans.getMTI() == '0800' and iso_ans.getBit(70)[1:] == '301':
                            Async(self.log.info('Echo Request Received'))
                            self.__keepAlive_REQ(iso_ans)
                        elif iso_ans.getMTI() == '0800' and iso_ans.getBit(70)[1:] == '001':
                            Async(self.log.info('Logon Request Received'))
                            self.__signon__REQ(iso_ans)
                        elif iso_ans.getMTI() == '0820' and iso_ans.getBit(70)[1:] == '101':
                            Async(self.log.info('Key Exchange Request Received'))
                        elif iso_ans.getMTI() == "0510":
                            Async(self.log.info('Reconciliation Request Response Received'))
                        elif iso_ans.getMTI() == "0530":
                            Async(self.log.info('Reconciliation Advice Response Received'))
                        else:
                            Async(self.log.warning('Unknown ISO Response Received'))
                        #Todo: Add host id here
                        Async(self.__storeISOMessage(iso_ans, {"date_time_received": d.strftime("%Y-%m-%d %H:%M:%S"), 'host_id': self.host_id}))

                        trace_sql = LogTrace(iso_ans, self.host_id, iso_ans.getMTI(), '')
                        Async(cur.execute(trace_sql))
                        self.MatchISOResponses(iso_ans.getBit(39))

                    except BitNotSet as e:
                        Async(self.log.critical("Bit was not set correctly [%s]" % (e)))
                        pass


        except socket.error as e:
            pass
            Async(self.log.debug("nothing from host [%s]" % (e)))
        finally:
            self.con_switch.commit()
            cur.close()

    def MatchISOResponses(self, response):
       #        Async(self.log.debug("Function Start: %s" % inspect.stack()[0][3])
       cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
       try:
           #TODO: add host id here
           sql = """
               UPDATE host_cuscal R INNER JOIN host_cuscal P
                   ON (R.p11_stan = P.p11_stan AND R.p7_transmit_dt = P.p7_transmit_dt)
               SET R.tran_gid = P.tran_gid,
                   R.source_node = P.source_node,
                   R.process_result = '%s',
                   P.process_result = '%s',
                   R.dt_processed = NOW(),
                   P.dt_processed = NOW()
               WHERE R.tran_gid IS NULL
                 AND R.dt_processed IS NULL
                 AND R.host_id = '%s'


               """ % (GetISOResponseText(response), GetISOResponseText(response), self.host_id)
           Async(cur.execute(sql))
           if cur.rowcount > 0:
               Async(self.log.debug("%s ISO Responses Linked" % cur.rowcount))
       finally:
           self.con_switch.commit()
           cur.close()
       #        Async(self.log.debug("Function End  : %s" % inspect.stack()[0][3])

    def __storeISOMessage(self, iso, extra=None):

        """
        Generic function to store any ISO response in the database
        """
        if not extra: extra = {}
        Async(self.log.debug('__storeISOMessage()'))
        cur = self.con_switch.cursor(MySQLdb.cursors.DictCursor)
        try:
            sql = Build_AS_Insert_Field_And_Values_for_Host_Node(iso, extra)
            Async(self.log.debug('sql = \n%s' % sql))
            rows_affected = cur.execute(sql)
            Async(self.log.debug('Rows Affected for INSERT = %s' % (rows_affected)))
            #print sql
        finally:
            self.con_switch.commit()
            cur.close()




def signal_handler():
    log.info("You pressed Ctrl+C")
    client.stop = True

if __name__ == '__main__':
    db = {'host':Config.switch_office_database_ip, 'port': Config.switch_office_database_port, 'dbuser':Config.switch_office_database_user, 'dbpassword':Config.switch_office_database_pwd, 'dbname':Config.switch_office_database}

    con = MySQLdb.Connect(host=db['host'], port=db['port'], db=db['dbname'], user=db['dbuser'], passwd=db['dbpassword'])
    cur = con.cursor(MySQLdb.cursors.DictCursor)

    sql = "SELECT id, host_name from host_config LIMIT 1"
    cur.execute(sql)
    Hosts = cur.fetchone()
    cur.close()

     # Setup the root logger to a file
    log = logging.getLogger()
    log.setLevel(level=logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(name)-16s %(levelname)-8s %(levelno)d %(message)s')





    #Add a second logger, showing the same stuff to stderr
    console = logging.StreamHandler()
    console.setLevel(level=logging.INFO)
    console.setFormatter(formatter)
    log.addHandler(console)

    #ql_logger_info = mySQLHandler(db)
    #log.addHandler(sql_logger_info)


    log.info('Starting')
    signal.signal(signal.SIGINT, signal_handler)

    client = HostNode(int(Hosts['id']), Hosts['host_name'])
    client.start()

    if not client.isAlive():

        try:
            time.sleep(1)
        except Exception:
            pass



    log.error('ALERT!!!! ---- Main() Ended ----- ALERT!!!!!')