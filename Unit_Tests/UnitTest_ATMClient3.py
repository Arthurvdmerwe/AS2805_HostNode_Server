import logging
import logging.handlers
import socket
import time
from random import randint
from threading import Thread

from Shared.StringToAscii import Str2Ascii, Ascii2Str
from Shared.EtxStx import AddLRC


class ATMClient(Thread):
    __ST_START = "ST_START"
    __ST_DONE = "ST_DONE"
    __ST_CONNECTING = "ST_CONNECTING"
    __ST_CONNECTED = "ST_CONNECTED"
    __ST_WAIT_FOR_ENQ = "ST_WAIT_FOR_ENQ"
    __ST_RECEIVED_ENQ = "ST_RECEIVED_ENQ"
    __ST_SENDING_REQ = "ST_SENDING_REQ"
    __ST_SENT_REQ = "ST_SENT_REQ"
    __ST_WAIT_FOR_RESPONSE = "ST_WAIT_FOR_RESPONSE"
    __ST_RECEIVED_RESPONSE = "ST_RECEIVED_RESPONSE"
    __ST_RESPONSE_OK = "ST_RESPONSE_OK"
    __ST_UNKNOWN_RESPONSE = "ST_UNKNOWN_RESPONSE"
    __ST_SENDING_ACK = "ST_SENDING_ACK"
    __ST_SENT_ACK = "ST_SENT_ACK"
    __ST_SENDING_EOT = "ST_SENDING_EOT"
    __ST_SENT_EOT = "ST_SENT_EOT"
    __ST_READ_TIMEOUT = "ST_READ_TIMEOUT"
    __ST_HOST_DISCONNECTED = "ST_HOST_DISCONNECTED"
    __ST_ERROR = "ST_ERROR"

    def __init__(self, atmid):
        super(ATMClient, self).__init__()
        self.Atm_ID = atmid
        self.host = '127.0.0.1'
        self.port = 9200
        self.prev_state = "NONE"
        self.state = "NONE"
        self.req = ""
        self.input = ""
        self.timing = {}
        self.res_count = 1



         # Setup the root logger to a file
        self.log = logging.getLogger()
        self.log.setLevel(level=logging.INFO)
        formatter = logging.Formatter('%(asctime)s %(name)-16s %(levelname)-8s %(message)s')

        # make sure the logging directory exists
        #dirname = "../Switch_Log/ATM_Client"
        #if not os.path.exists(dirname):
        #    os.makedirs(dirname)


        # Add rotating file handler to logger
        #handler = logging.handlers.TimedRotatingFileHandler(dirname + '/debug.log', when="MIDNIGHT", backupCount=90)
        #handler.setLevel(logging.DEBUG)
        #handler.setFormatter(formatter)
        #self.log.addHandler(handler)

        # Add another one to log all INFO stuff to a different file
        #info = logging.handlers.TimedRotatingFileHandler(dirname + '/info.log', when="MIDNIGHT", backupCount=90)
        #info.setLevel(logging.INFO)
        #info.setFormatter(formatter)
        #self.log.addHandler(info)

        # Add another one to log all CRITICAL stuff to a different file
        #critical = logging.handlers.TimedRotatingFileHandler(dirname + '/critical.log', when="MIDNIGHT", backupCount=90)
        #critical.setLevel(logging.CRITICAL)
        #critical.setFormatter(formatter)
        #self.log.addHandler(critical)

        # Add a second logger, showing the same stuff to stderr
        console = logging.StreamHandler()
        console.setLevel(self.log.level)
        console.setFormatter(formatter)
        self.log.addHandler(console)
        # ## -- End of logging code --#######################################################################

    def __reset_timing(self):
        # Reset the internal timing
        self.timing = {}
        self.res_count = 1

    def Connect(self):
        self.log.debug("Connecting to %s:%s" % (self.host, self.port))

        self.__reset_timing()

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(70.0)
        self.set_state(self.__ST_CONNECTING)
        self.timing['connecting'] = time.time()
        self.s.connect((self.host, self.port))

        self.timing['connected'] = time.time()
        self.set_state(self.__ST_CONNECTED)
        self.log.debug("Connected")


    def Read(self, timeout=65.0):
        self.log.debug("Waiting for Packet")
        self.s.settimeout(timeout)
        try:
            self.input = self.s.recv(1024)
        except socket.timeout:
            self.log.info("timeout")
            self.set_state(self.__ST_READ_TIMEOUT)
        if self.input == "":
            self.log.info("Host Disconnected")
            self.set_state(self.__ST_HOST_DISCONNECTED)
        else:
            self.input = Str2Ascii(self.input)
            self.timing['res_%02d' % self.res_count] = time.time()
            self.res_count += 1
            self.log.info("Packet Received = [%s]" % self.input)


    def SendCWReversal(self):
        raw = ""
        raw += "<STX>DMXMD   td7W0       <FS>%s" % self.Atm_ID
        raw += "<FS>29<FS>0001<FS>4564811090200072=12121011311515260000<FS>00012000<FS>00000200<FS>00004000<FS>VA5.00.07WV02.70.10 V04.00.19 0  0T  00 000     01800002K0200000000002K050000020000000000000000000000000000000000<FS>^E02E 5183<FS><ETX>"
        # raw.Append("<ETX>")
        raw = Str2Ascii(AddLRC(Ascii2Str(raw)))

        self.log.info("Sending [%s]" % (raw))
        self.timing['req_send'] = time.time()
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))


    def SendBIAuthorization(self):
        raw = ""
        raw += "<STX>000000  td3W0       <FS>%s" % self.Atm_ID
        raw += "<FS>35<FS>0137<FS>4089670000392726=17112011000013910000<FS>00000000<FS>00000100<FS>8CFD26F840F4F942<FS><FS><FS>VA5.00.03WV02.70.10 V04.00.19 0  0T  00 000     00000002K0111000100005K000002220060000000000000000000000000000000<FS>^61D2 1C32<FS><ETX>"
        # raw.Append("<ETX>")
        raw = Str2Ascii(AddLRC(Ascii2Str(raw)))

        self.log.info("Sending [%s]" % (raw))
        self.timing['req_send'] = time.time()
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))

    def SendHostTotals(self):
        raw = ""
        raw += "<STX>000000  td3W0       <FS>9%s" % self.Atm_ID
        raw += "<FS>50<FS>VA5.00.03WV02.70.10 V04.00.19 0  0T  00 000     D0000002K0111000100005K000002220060000000000000000000000000000000<FS>^C461 D689<FS><ETX>"
        # raw.Append("<ETX>")
        raw = Str2Ascii(AddLRC(Ascii2Str(raw)))

        self.log.info("Sending [%s]" % (raw))
        self.timing['req_send'] = time.time()
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))

    def SendConfigRequest(self):
        raw = ""
        raw += "<STX>000000  td3W0       <FS>%s" % self.Atm_ID
        raw += "<FS>60<FS>VA5.00.03WV02.70.10 V04.00.19 0  0T  00 000     00000002K0111000100005K000002220060000000000000000000000000000000<FS><ETX>"
        # raw.Append("<ETX>")
        raw = Str2Ascii(AddLRC(Ascii2Str(raw)))

        self.log.info("Sending [%s]" % (raw))
        self.timing['req_send'] = time.time()
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))

    def SendCWAuthorization(self):
        # Config
        raw = ""
        raw += "<STX>00000000td2W0       <FS>%s       " % self.Atm_ID
        TranAmount = (str(randint(20,700)) + "00").zfill(8) #inclusive
        Surcharge = (str(randint(1,3)) + "00").zfill(8)
        Status =    "VA6.00.12W"
        Status +=   "V02.70.10 "
        Status +=   "V06.01.12 "
        Status +=   "0  0T  00 "
        Status +=   str(randint(0, 2))   #TODO: change status automatically - Dispenser
        Status +=   str(randint(0, 2))   #TODO: change status automatically - Comms System
        Status +=   "0     "
        Status +=   "000" #TODO: change status automatically - Terminal Error Code
        Status +=   str(randint(0, 10)).zfill(3) #TODO: change status automatically - Comms failures
        Status +=   "02K0288000000002K028800000000000000000000000000000000000000"
        raw += "<FS>11<FS>0002<FS>4089670000392726=17112011000017980000<FS>"+TranAmount+"<FS>"+Surcharge+"<FS>76728398F76ED27D<FS><FS><FS>" + Status + "<FS>ud9F0607A000000003101082023C009F360200AC9F2608B296C158187785D59F2701809F100706010A03A0B800950580000400009F3704AF3FA1785F3401019F1A0201245F2A0201249A031409239C01019F4104000000039F1E0830303030303030319F33036048009F3501148E14000000000000000002010205440342031E031F029F34030201009F3901059B026000<FS><FS><ETX>"
        # raw.Append("<ETX>")
        raw = Str2Ascii(AddLRC(Ascii2Str(raw)))

        self.log.info("Sending [%s]" % (raw))
        self.timing['req_send'] = time.time()
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))


    def SendReq(self):
        self.log.info("Sending [%s]" % (self.req))
        self.set_state(self.__ST_SENDING_REQ)
        self.timing['req_send'] = time.time()
        x = self.s.send(Ascii2Str(self.req))
        self.log.info("%d bytes sent" % (x))
        self.set_state(self.__ST_SENT_REQ)


    def SendACK(self):
        raw = "<ACK>"

        self.set_state(self.__ST_SENDING_ACK)
        self.log.info("Sending [%s]" % (raw))
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))
        self.set_state(self.__ST_SENT_ACK)


    def SendEOT(self):
        raw = "<EOT>"

        self.set_state(self.__ST_SENDING_EOT)
        self.log.info("Sending [%s]" % (raw))
        x = self.s.send(Ascii2Str(raw))
        self.log.info("%d bytes sent" % (x))
        self.set_state(self.__ST_SENT_EOT)


    def Disconnect(self):
        self.log.debug("Disconnecting")
        self.s.close()
        self.log.info("Disconnected")


    def set_state(self, new_state):
        self.log.info("State Changed From [%s] to [%s], Previous State = [%s]" % (self.state, new_state, self.prev_state))
        self.prev_state = self.state
        self.state = new_state


    def __do_wait_for_ENQs(self):
        self.set_state(self.__ST_WAIT_FOR_ENQ)
        self.Read(90)
        if self.state == self.__ST_WAIT_FOR_ENQ:
            if self.input == "<ENQ>":
                self.set_state(self.__ST_RECEIVED_ENQ)


    def __do_wait_for_response(self):
        self.set_state(self.__ST_WAIT_FOR_RESPONSE)
        self.Read(90)
        if self.state == self.__ST_WAIT_FOR_RESPONSE:
            self.set_state(self.__ST_RECEIVED_RESPONSE)


    def Process_HealthMessage(self):
        self.log.info("Process_HealthMessage()")
        self.set_state(self.__ST_RESPONSE_OK)

    def Process_Authorization(self):
        self.log.info("Process_Authorization()")
        self.set_state(self.__ST_RESPONSE_OK)

    def Process_Reversal(self):
        self.log.info("Process_Reversal()")
        self.set_state(self.__ST_RESPONSE_OK)

    def Process_HostTotals(self):
        self.log.info("Process_HostTotals()")
        self.set_state(self.__ST_RESPONSE_OK)

    def Process_Configuration(self):
        self.log.info("Process_Configuration()")
        self.LocalDate = self.fields[3][:8]
        self.log.debug("LocalDate            = [%s]" % self.LocalDate)
        self.LocalTime = self.fields[3][8:]
        self.log.debug("LocalTime            = [%s]" % self.LocalTime)
        self.HealthInterval = self.fields[4]
        self.log.debug("HealthInterval       = [%s]" % self.HealthInterval)
        self.WorkingKeyPart1 = self.fields[5]
        self.log.debug("WorkingKeyPart1      = [%s]" % self.WorkingKeyPart1)
        self.SurchargeAmount = self.fields[6]
        self.log.debug("SurchargeAmount      = [%s]" % self.SurchargeAmount)
        self.BinListEnabled = self.fields[7]
        self.log.debug("BinListEnabled       = [%s]" % self.BinListEnabled)
        self.WorkingKeyPart2 = self.fields[8]
        self.log.debug("WorkingKeyPart2      = [%s]" % self.WorkingKeyPart2)
        self.WorkingKeyPart1Again = self.fields[9]
        self.log.debug("WorkingKeyPart1Again = [%s]" % self.WorkingKeyPart1Again)
        self.set_state(self.__ST_RESPONSE_OK)


    def process_response(self):
        self.log.debug("process_response")
        noetx = self.input.split("<ETX>")
        stx = noetx[0]
        nostx = stx[5:]
        self.fields = nostx.split("<FS>")
        self.log.info("REQ fields=%s" % (self.fields))
        Command = self.fields[2]
        if Command == "H0":
            self.Process_HealthMessage()
        elif Command == "85":
            self.Process_Authorization()
        elif Command == "86":
            self.Process_Reversal()
        elif Command == "87":
            self.Process_HostTotals()
        elif Command == "88":
            self.Process_Configuration()
        else:
            self.set_state(self.__ST_UNKNOWN_RESPONSE)

        if self.state == self.__ST_RESPONSE_OK:
            self.timing['res'] = self.timing['res_%02d' % (self.res_count - 1)]


    def __do_session(self):
        self.set_state(self.__ST_START)
        # State Engine
        while self.state not in [self.__ST_DONE, self.__ST_ERROR]:
            if self.state == self.__ST_START:
                self.Connect()
            elif self.state == self.__ST_CONNECTED:
                self.__do_wait_for_ENQs()
            elif self.state == self.__ST_RECEIVED_ENQ:
                self.SendReq()
            elif self.state == self.__ST_SENT_REQ:
                self.__do_wait_for_response()
            elif self.state == self.__ST_RECEIVED_RESPONSE:
                self.process_response()
                pass
            elif self.state == self.__ST_RESPONSE_OK:
                self.SendACK()
            elif self.state == self.__ST_SENT_ACK:
                self.SendEOT()
            elif self.state == self.__ST_SENT_EOT:
                self.Read(10)
            elif (self.state == self.__ST_HOST_DISCONNECTED) and (self.prev_state == self.__ST_SENT_EOT):
                self.set_state(self.__ST_DONE)
            else:
                self.log.info("Unexpected State [%s]" % self.state)
                self.set_state(self.__ST_ERROR)


    def DoConfig(self):
        # <STX>H0.366669<FS>SAS00001<FS>88<FS>06282010001730<FS>000000<FS>06D2D993834DA802<FS>0000<FS>0<FS>72D8C7311C876FC3<FS>06D2D993834DA802<ETX>{
        self.log.debug("DoConfig()")
        raw = ""
        raw += "<STX>000000  td3W0       <FS>%s" % self.Atm_ID
        raw += "<FS>60<FS>VA5.00.03WV02.70.10 V04.00.19 0  0T  00 000     00000002K0111000100005K000002220060000000000000000000000000000000<FS><ETX>"
        # raw.Append("<ETX>")
        raw = Str2Ascii(AddLRC(Ascii2Str(raw)))

        self.req = raw
        self.__do_session()
        if self.state == self.__ST_DONE:
            pass


    def ShowTiming(self):
      #  self.log.info("timing = %s" % atm.timing)
        time_con = self.timing['connected'] - self.timing['connecting']
        # time_res = self.timing['res_01'] - self.timing['req_send']
        self.log.info("Timing: CON[%08.4F], RES[%08.4F]" % (time_con, 0))


"""
    def run(self):
        self.Connect()
        self.Read(30.0)
        self.SendCWAuthorization()
        self.Read(90.0)

        self.SendACK()
        self.Read(30.0)
        self.SendEOT()
        self.Read(30.0)
        self.Disconnect()

"""

while True:

    atm = ATMClient('S9218165')
    atm.Connect()
    atm.Read(30.0)
    atm.SendCWAuthorization()
    atm.Read(90.0)

    atm.SendACK()
    atm.Read(30.0)
    atm.SendEOT()
    atm.Read(30.0)
    atm.Disconnect()







        #self.log.info("timing = %s" % atm.timing)
        #self.log.info("Done")
        #time.sleep(1)
    


