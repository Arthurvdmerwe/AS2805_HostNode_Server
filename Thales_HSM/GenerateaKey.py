__author__ = 'root'
import logging
import os
import logging.handlers
from Shared.StringToAscii import Ascii2Str
from Thales_HSM import Connector
from Shared.ByteUtils import ByteToHex, HexToByte


class GenerateKey:

    def __init__(self):
        pass

    def get_commandTPK(self, TMK):
        command_code = 'A0'
        Mode = '1'
        KeyType = '002'
        TMK_ZMK_Flag = '1'
        KeyScheme = 'U'
        TMK = TMK
        Exporting_Key_Scheme = 'X'

        message =  command_code
        message += Mode
        message += KeyType
        message += KeyScheme + ';'
        message += TMK_ZMK_Flag
        message += TMK
        message += Exporting_Key_Scheme
        #print message
        return message

    def get_generate_random_number(self):
        command_code = 'C6'
        message = command_code
        return message

    def get_commandTAK_MAC(self, TMK):
        command_code = 'A0'
        Mode = '1'
        KeyType = '003'
        TMK_ZMK_Flag = '1'
        KeyScheme = 'U'
        TMK = TMK
        Exporting_Key_Scheme = 'X'

        message =  command_code
        message += Mode
        message += KeyType
        message += KeyScheme + ';'
        message += TMK_ZMK_Flag
        message += TMK
        message += Exporting_Key_Scheme
        #print message
        return message

    def get_commandTranslateKey(self, KeyType, Key, toScheme):
        command_code = 'B0'

        KeyType = KeyType
        Key = Key
        KeyScheme = toScheme

        message =  command_code
        message += KeyType
        message += Key
        message += KeyScheme

        #print message
        return message

    def get_commandGenerateaSetofZoneKeys(self, KEKs):

        command_code = 'OI'
        KEKs =  KEKs
        message = command_code
        message += KEKs
        message += ';HU1;1'
        #print message
        return message

    def get_commandTranslateaSetofZoneKeys(self, KEKr, ZPK, ZAK, ZEK):

        command_code = 'OK'
        KEKr =  KEKr
        KVC_Processing_Flag = '2'
        ZPK_Flag = '1'
        ZPK = 'H'+ ZPK
        ZAK_Flag = '1'
        ZAK = 'H'+ ZAK
        ZEK_Flag = '0'
        ZEK = 'H'+ '11111111111111111111111111111111'


        message = command_code
        message += KEKr
        message += KVC_Processing_Flag
        message += ZPK_Flag
        message += ZPK
        message += ZAK_Flag
        message += ZAK
        message += ZEK_Flag
        message += ZEK
        message += ';HU1'
        #print message
        return message

    def get_commandTPKPinBlock(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

        command_code = 'D4'
        KTP = TerminalPINKey
        KPE = PINEncryptionKey
        PinBlock = PINBlock
        PAN = AccountNumber


        message = command_code
        message += KTP
        message += KPE
        message += PinBlock
        message += PAN
        #print message
        return message

    def get_commandTPKPinBlock_CA(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

        command_code = 'CA'
        KTP = TerminalPINKey
        KPE = PINEncryptionKey
        Pin_Length = '12'
        PinBlock = PINBlock
        PinBlockFormat = '0101'
        PAN = AccountNumber


        message = command_code
        message += KTP
        message += KPE
        message += Pin_Length
        message += PinBlock
        message += PinBlockFormat
        message += PAN
        print message
        return message

    def get_commandTMK(self):
        Mode = '0'
        command_code = 'A0'
        KeyType = '002'
        KeyScheme = 'U'

        message = command_code
        message += Mode
        message += KeyType
        message += KeyScheme
        #print message
        return message

    def get_commandKey(self, KeyType):
        Mode = '0'
        command_code = 'A0'
        keyType = KeyType
        KeyScheme = 'U'

        message = command_code
        message += Mode
        message += keyType
        message += KeyScheme
        #print message
        return message

    def get_PIN_Pad_Acquirer_Security_Number(self, Acquirer_Key_TMK, PIN_Pad_Serial_Number):
        command_code = 'PK'
        acquirer_key = Acquirer_Key_TMK
        pin_pad_serial_number = PIN_Pad_Serial_Number
        delimiter = ';'
        kia_key_indicator = '2'
        message  = command_code
        message += acquirer_key
        message += pin_pad_serial_number
        message += delimiter
        message += kia_key_indicator
        return message

    def get_commandDecrypt_a_PIN_Pad_Public_Key(self, Mac, Manufacturer_Public_Key, sMSK_PPPK, PPPK_Exponent=None):
        command_code = 'H0'
        key_encoding = '01'
        mac = Mac
        public_key = Manufacturer_Public_Key
        delimiter = ';'
        secret_Key_flag = '99'
        data_length = str(len(sMSK_PPPK)).zfill(4)# must convert hex to byte
        cmsk_pppk = sMSK_PPPK
        if PPPK_Exponent is not None:
            exponent_length = str(len(PPPK_Exponent)).zfill(4)
            PPPK_Exponent = PPPK_Exponent


        message  = command_code
        message += key_encoding
        message += mac
        message += public_key
        message += delimiter

        message += data_length
        message += cmsk_pppk

        if PPPK_Exponent is not None:
            message += delimiter
            message += exponent_length
            message += PPPK_Exponent

        return message

    def Calculate_a_RSA_Public_Key_Verification_Code(self, Encoding, Public_Key):
        command_code = 'H2'
        encoding = Encoding
        public_key = Public_Key

        message = command_code
        message += encoding
        message += public_key
        return message

    def get_commandEncrypt_a_Cross_Acquirer_Key_Encrypting_Key_under_an_Initial_Transport_Key(self, Mac, Pinpad_Public_Key, Secret_Key,Secrect_Key_Leghth, DataBlock, RandomNumber):
        command_code = 'H8'
        public_key_encoding = '01'
        mac = Mac
        pinpad_public_key = Pinpad_Public_Key
        delimiter = ';'
        secret_key_flag = '99'
        secret_key_length = Secrect_Key_Leghth.decode("hex").zfill(4)
        secret_key = Secret_Key
        data_length = str(len(DataBlock)).zfill(4)
        data_block = DataBlock
        random_number = RandomNumber
        #rest = ';000'

        message = command_code
        message += public_key_encoding
        message += mac
        message += pinpad_public_key
        message += delimiter
        message += secret_key_flag
        message += secret_key_length
        message += secret_key
        message += delimiter
        message += data_length
        message += data_block
        message += delimiter
        message += random_number
        #message += rest

        return message

    def get_RSA(self):

        command_code = 'EI'
        #keyType: 2- Key and management, 0-signature only, 1-key management only, 3-icc key, 4-ssl
        KeyType = '2'
        KeyLength = '0896'
        PublicKeyEncoding = '01'
        #public_exponent_length = '0016'
        #public_exponent = HexToByte('BA7F')




        message = command_code
        message += KeyType
        message += KeyLength
        message += PublicKeyEncoding
        #message += public_exponent_length
        #message += public_exponent

        return message

    def get_commandTAK(self):
        Mode = '0'
        command_code = 'A0'
        KeyType = '003'
        KeyScheme = 'X'

        message = command_code
        message += Mode
        message += KeyType
        message += KeyScheme
        print message
        return message

    def get_commandGenerate_KEKr_Validation_Response(self, KEKr, KRs):

        command_code = 'E2'
        KEKr =  KEKr
        KRs = KRs

        message = command_code
        message += KEKr
        message += KRs
        #print "E2 Message = " + message
        return message

    def get_commandImport_a_Public_Key(self, Public_Key):
        command_code = 'EO'
        encoding = '01'
        key = Public_Key

        message = command_code
        message += encoding
        message += key

        return message

    def get_commandGenerate_KEKs_Validation_Request(self, KEKs):
        command_code = 'E0'
        KEKs = KEKs

        message = command_code
        message +=  KEKs
        return message

    def convert(self, int_value):
        encoded = format(int_value, 'x')
        length = len(encoded)
        encoded = encoded.zfill(length+length%2)
        return encoded.decode('hex')

    def get_commandGenerateMAC(self, Message, MAC_Key):
        #Message = Message.encode('hex')
        print len(Message)
        #if len(Message) %2 != 0:
        #   Message += '0'
        print len(Message)
        Len = hex(len(Message))[2:].zfill(4).upper()

        Message_Block = Message
        command_code = 'C2'
        Block_No = '0'
        MAC_Key_Type = '3'
        Mac_Generation_Mode = '3'

        Message_Type = '0'
        Key = MAC_Key
        Message_Length = Len

        message = command_code
        message += Block_No
        message += MAC_Key_Type
        message += Mac_Generation_Mode
        message += Message_Type
        message += Key
        message += Message_Length
        message += Message_Block
        print message
        return message

    def get_commandVerifyMAC(self, MAC, Message, Length, Key):
        message = 'C40320'
        message += Key
        message += MAC
        message += Length
        message += Message
        print message
        return message

    def execute_get_Generate_KEKr_Validation_Response(self,KEKr, KRs):
        response = Connector.Thales9000().SendMessage(self.get_commandGenerate_KEKr_Validation_Response(KEKr, KRs))
        return response

    def execute_Translate_a_Set_of_Zone_Keys(self, KEKr, ZPK, ZAK, ZEK):
        response = Connector.Thales9000().SendMessage(self.get_commandTranslateaSetofZoneKeys(KEKr, ZPK, ZAK, ZEK))
        return response

    def execute_get_a_Set_of_Zone_Keys(self, KEKs):
        response = Connector.Thales9000().SendMessage(self.get_commandGenerateaSetofZoneKeys(KEKs))
        return response

    def execute_get_Generate_KEKs_Validation_Request(self,KEKs):
        response = Connector.Thales9000().SendMessage(self.get_commandGenerate_KEKs_Validation_Request(KEKs))
        return response

    def execute_GenerateTMK(self):
        response = Connector.Thales9000().SendMessage(self.get_commandTMK())
        print response
        return response

    def execute_GenerateKey(self, KeyType):
        response = Connector.Thales9000().SendMessage(self.get_commandKey(KeyType))
        #print response
        return response

    def execute_generate_a_random_number(self):
        response = Connector.Thales9000().SendMessage(self.get_generate_random_number())
        return response

    def execute_GenerateTPK(self, TMK):
        response = Connector.Thales9000().SendMessage(self.get_commandTPK(TMK))
        return response

    def execute_Generate_PIN_Pad_Acquirer_Security_Number(self, Acquirer_Key_TMK, PIN_Pad_Serial_Number):
        response = Connector.Thales9000().SendMessage(self.get_PIN_Pad_Acquirer_Security_Number(Acquirer_Key_TMK, PIN_Pad_Serial_Number))
        return response

    def execute_Decrypt_a_PIN_Pad_Public_Key(self, Mac, Manufacturer_Public_Key, sMSK_PPPK, PPPK_Exponent=None):
        response = Connector.Thales9000().SendMessage(self.get_commandDecrypt_a_PIN_Pad_Public_Key(Mac, Manufacturer_Public_Key, sMSK_PPPK, PPPK_Exponent))
        return response

    def execute_GenerateTAK_MAC(self, TMK):
        response = Connector.Thales9000().SendMessage(self.get_commandTAK_MAC(TMK))
        return response

    def execute_TranslateKey(self,  KeyType, Key, toScheme):
        response = Connector.Thales9000().SendMessage(self.get_commandTranslateKey(KeyType, Key, toScheme))
        return response

    def execute_TranslatePin(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):
        response = Connector.Thales9000().SendMessage(self.get_commandTPKPinBlock(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber))
        return response

    def execute_TranslatePin_CA(self, TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):
        response = Connector.Thales9000().SendMessage(self.get_commandTPKPinBlock_CA(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber))
        return response

    def execute_GenerateTAK(self,):
        response = Connector.Thales9000().SendMessage(self.get_commandTAK())
        #print response
        return response

    def execute_Import_Public_Key(self,Public_Key):
        response = Connector.Thales9000().SendMessage(self.get_commandImport_a_Public_Key(Public_Key))
        #print response
        return response

    def execute_GenerateMAC(self, Message, Key):
        response = Connector.Thales9000().SendMessage(self.get_commandGenerateMAC(Message, Key))
        return response

    def execute_Encrypt_a_Cross_Acquirer_Key_Encrypting_Key_under_an_Initial_Transport_Key(self, Mac, Pinpad_Public_Key, Secret_Key,Secrect_Key_Leghth,  DataBlock, RandomNumber):
        response = Connector.Thales9000().SendMessage(self.get_commandEncrypt_a_Cross_Acquirer_Key_Encrypting_Key_under_an_Initial_Transport_Key(Mac, Pinpad_Public_Key, Secret_Key,Secrect_Key_Leghth,  DataBlock, RandomNumber))
        return response

    def execute_VerifyMac(self, MAC, Message, Length, Key):
        response = Connector.Thales9000().SendMessage(self.get_commandVerifyMAC(MAC, Message, Length, Key))
        return response

    def execute_GenerateRSAKeyPair(self, ):
        response = Connector.Thales9000().SendMessage(self.get_RSA())
        return response

    def sendMessage(self, message):
        response = Connector.Thales9000().SendMessage(message)
        return response

def __init__():


        # Setup the root logger to a file
        log = logging.getLogger()
        log.setLevel(level=logging.INFO)
        formatter = logging.Formatter('%(asctime)s %(name)-16s %(levelname)-8s %(message)s')

        # make sure the logging directory exists
        dirname = "../Switch_Log/HSM_Node"
        if not os.path.exists(dirname):
            os.makedirs(dirname)


        # Add rotating file handler to logger
        handler = logging.handlers.TimedRotatingFileHandler(dirname + '/debug.log', when="MIDNIGHT", backupCount=90)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        log.addHandler(handler)

        # Add another one to log all INFO stuff to a different file
        info = logging.handlers.TimedRotatingFileHandler(dirname + '/info.log', when="MIDNIGHT", backupCount=90)
        info.setLevel(logging.INFO)
        info.setFormatter(formatter)
        log.addHandler(info)

        #Add another one to log all CRITICAL stuff to a different file
        critical = logging.handlers.TimedRotatingFileHandler(dirname + '/critical.log', when="MIDNIGHT", backupCount=90)
        critical.setLevel(logging.CRITICAL)
        critical.setFormatter(formatter)
        log.addHandler(critical)

        #Add a second logger, showing the same stuff to stderr
        console = logging.StreamHandler()
        console.setLevel(log.level)
        console.setFormatter(formatter)
        log.addHandler(console)
        ### -- End of logging code --#######################################################################
