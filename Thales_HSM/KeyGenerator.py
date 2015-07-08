__author__ = 'root'

from Thales_HSM.GenerateaKey import *
import binascii, string

KeyClass = GenerateKey()

def GenerateKeys(KeyType):
    response = KeyClass.execute_GenerateKey(KeyType)
    #print response
    Response = {}
    Response["Header"] = response[2:6]
    Response["ResponseCode"] = response[6:8]
    Response["ErrorCode"] = response[8:10]
    if Response["ErrorCode"] == '00':
        Response["TMK"] = response[10:43]
        Response["TMK_Check"] = response[43:76]

    return Response

def GenerateKeys_TMK():
    response = KeyClass.execute_GenerateTMK()
    #print response
    ResponseTMK = {}
    ResponseTMK["Header"] = response[2:6]
    ResponseTMK["ResponseCode"] = response[6:8]
    ResponseTMK["ErrorCode"] = response[8:10]
    if ResponseTMK["ErrorCode"] == '00':
        ResponseTMK["TMK"] = response[10:43]
        ResponseTMK["TMK_Check"] = response[43:76]

    return ResponseTMK

def GenerateKeys_Public_Private_Key_Pair():
    response = KeyClass.execute_GenerateRSAKeyPair()
    ResponsePubPriKey = {}
    ResponsePubPriKey["Header"] = response[2:6]
    ResponsePubPriKey["ResponseCode"] = response[6:8]
    ResponsePubPriKey["ErrorCode"] = response[8:10]
    if ResponsePubPriKey["ErrorCode"] == '00':
        ResponsePubPriKey["Data"] =  response[10:]
        #ResponsePubPriKey["PublicKey"] = response[10:256]
        #ResponsePubPriKey["PrivateKeyLength"] = response[256:260]
        #ResponsePubPriKey["PrivateKey"] = response[260:]
        string_hex =  str(binascii.b2a_hex(ResponsePubPriKey["Data"])).upper()
        string_hex =  ResponsePubPriKey["Data"]
        #print string_hex
        #print binascii.b2a_base64(ResponsePubPriKey["Data"])
        #print str(ResponsePubPriKey["Data"])

    return ResponsePubPriKey

def GenerateKeys_TAK():
    response = KeyClass.execute_GenerateTAK()
    ResponseTAK = {}
    ResponseTAK["Header"] = response[2:6]
    ResponseTAK["ResponseCode"] = response[6:8]
    ResponseTAK["ErrorCode"] = response[8:10]
    if ResponseTAK["ErrorCode"] == '00':
        ResponseTAK["TAK"] = response[10:43]
        ResponseTAK["TAK_Check"] = response[43:76]
    return ResponseTAK

def GenerateSessionKeys(TMK):
    response = KeyClass.execute_GenerateTPK(TMK)
    ResponseTPK = {}
    #print response
    ResponseTPK["Header"] = response[2:6]
    ResponseTPK["ResponseCode"] = response[6:8]
    ResponseTPK["ErrorCode"] = response[8:10]
    if ResponseTPK["ErrorCode"] == '00':
        ResponseTPK["TPK_LMK"] = response[10:43]
        ResponseTPK["TPK"] = response[43:76]
        ResponseTPK["TPK_Check"] = response[76:82]
        return ResponseTPK

def GenerateMACKeys(TMK):
    response = KeyClass.execute_GenerateTAK_MAC(TMK)
    ResponseTPK = {}
    #print response
    ResponseTPK["Header"] = response[2:6]
    ResponseTPK["ResponseCode"] = response[6:8]
    ResponseTPK["ErrorCode"] = response[8:10]
    if ResponseTPK["ErrorCode"] == '00':
        ResponseTPK["TAK"] = response[10:43]
        ResponseTPK["TAK_LMK"] = response[43:76]
        ResponseTPK["TAK_Check"] = response[76:82]
        return ResponseTPK

def TranslateKeyScheme( KeyType, Key, toScheme):
    response = KeyClass.execute_TranslateKey( KeyType, Key, toScheme)
    TranslateKeyScheme = {}
    print response
    TranslateKeyScheme["Header"] = response[2:6]
    TranslateKeyScheme["ResponseCode"] = response[6:8]
    TranslateKeyScheme["ErrorCode"] = response[8:10]
    if TranslateKeyScheme["ErrorCode"] == '00':
        TranslateKeyScheme["Key"] = response[10:43]
        return TranslateKeyScheme

def TranslatePIN_TDES(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

    response = KeyClass.execute_TranslatePin(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber)
    #print response
    TranslatePIN_TDES_Response = {}
    TranslatePIN_TDES_Response["Header"] = response[2:6]
    TranslatePIN_TDES_Response["ResponseCode"] = response[6:8]
    TranslatePIN_TDES_Response["ErrorCode"] = response[8:10]
    if TranslatePIN_TDES_Response["ErrorCode"] == '00':
        TranslatePIN_TDES_Response["DestPIN"] = response[10:26]
        return TranslatePIN_TDES_Response

def TranslatePIN_TDES_CA(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber):

    response = KeyClass.execute_TranslatePin_CA(TerminalPINKey, PINEncryptionKey, PINBlock, AccountNumber)
    #print response
    TranslatePIN_TDES__CA_Response = {}
    TranslatePIN_TDES__CA_Response["Header"] = response[2:6]
    TranslatePIN_TDES__CA_Response["Status"] = response[6:8]
    if TranslatePIN_TDES__CA_Response["Status"] == '00':
        TranslatePIN_TDES__CA_Response["DestPIN"] = response[8:24]
        return TranslatePIN_TDES__CA_Response

def Generate_KEKr_Validation_Response(KEKr, KRs):
    response = KeyClass.execute_get_Generate_KEKr_Validation_Response(KEKr, KRs)
    KEKr_Validation_Response = {}
    #print response
    KEKr_Validation_Response["Header"] = response[2:6]
    KEKr_Validation_Response["ResponseCode"] = response[6:8]
    KEKr_Validation_Response["ErrorCode"] = response[8:10]
    if KEKr_Validation_Response["ErrorCode"] == '00':
        KEKr_Validation_Response["KRr"] = response[10:]
    return KEKr_Validation_Response

def Generate_KEKs_Validation_Request(KEKs):
    response = KeyClass.execute_get_Generate_KEKs_Validation_Request(KEKs)
    KEKs_Validation_Request = {}
    KEKs_Validation_Request["Header"] = response[2:6]
    KEKs_Validation_Request["ResponseCode"] = response[6:8]
    KEKs_Validation_Request["ErrorCode"] = response[8:10]
    if KEKs_Validation_Request["ErrorCode"] == '00':
        KEKs_Validation_Request["KRs"] = response[11:27]
        KEKs_Validation_Request["KRr"] = response[27:75]
    return KEKs_Validation_Request

def VerifyMAC(MAC, Message, Length, Key):
    response = KeyClass.execute_VerifyMac(MAC, Message, Length, Key)
    print response

def Generate_PIN_Pad_Acquirer_Security_Number(Acquirer_Key_TMK, PIN_Pad_Serial_Number):
    response = KeyClass.execute_Generate_PIN_Pad_Acquirer_Security_Number(Acquirer_Key_TMK, PIN_Pad_Serial_Number)
    PPASN = {}
    PPASN["Header"] = response[2:6]
    PPASN["ResponseCode"] = response[6:8]
    PPASN["ErrorCode"] = response[8:10]
    if PPASN["ErrorCode"] == '00':
        PPASN["PPASN(LMK)"] = response[10:26]
        PPASN["PPASN(KIA)"] = response[26:42]

    return PPASN

def Decrypt_a_PIN_Pad_Public_Key( Mac, Manufacturer_Public_Key, sMSK_PPPK, PPPK_Exponent=None):
    response = KeyClass.execute_Decrypt_a_PIN_Pad_Public_Key(Mac, Manufacturer_Public_Key, sMSK_PPPK, PPPK_Exponent)
    Response = {}
    Response["Header"] = response[2:6]
    Response["ResponseCode"] = response[6:8]
    Response["ErrorCode"] = response[8:10]
    if Response["ErrorCode"] == '00':
        Response["PPPK"] = response[10:-4]
        Response["MAC"] = response[-4:]
    return  Response

def Generate_a_Random_Number():
    response = KeyClass.execute_generate_a_random_number()
    RandomNumber = {}
    RandomNumber["Header"] = response[2:6]
    RandomNumber["ResponseCode"] = response[6:8]
    RandomNumber["ErrorCode"] = response[8:10]
    if RandomNumber["ErrorCode"] == '00':
        RandomNumber["RandomNumber"] = response[10:26]

    return RandomNumber

def Generate_a_Set_of_Zone_Keys(KEKs):
    response = KeyClass.execute_get_a_Set_of_Zone_Keys(KEKs)
    #print response
    ZoneKeys = {}
    ZoneKeys["Header"] = response[2:6]
    ZoneKeys["ResponseCode"] = response[6:8]
    ZoneKeys["ErrorCode"] = response[8:10]
    if ZoneKeys["ErrorCode"] == '00':
        ZoneKeys["ZPK(LMK)"] = response[10:43]
        ZoneKeys["ZPK(ZMK)"] = response[43:76]
        ZoneKeys["ZPK Check Value"] = response[76:82]
        ZoneKeys["ZAK(LMK)"] = response[82:115]
        ZoneKeys["ZAK(ZMK)"] = response[115:148]
        ZoneKeys["ZAK Check Value"] = response[148:154]
        ZoneKeys["ZEK(LMK)"] = response[154:187]
        ZoneKeys["ZEK(ZMK)"] = response[187:220]
        ZoneKeys["ZEK Check Value"] = response[220:226]
    return ZoneKeys

def Translate_a_Set_of_Zone_Keys(KEKr, ZPK, ZAK, ZEK):
    response = KeyClass.execute_Translate_a_Set_of_Zone_Keys(KEKr, ZPK, ZAK, ZEK)
    #print response
    TranslatedZoneKeys = {}
    TranslatedZoneKeys["Header"] = response[2:6]
    TranslatedZoneKeys["ResponseCode"] = response[6:8]
    TranslatedZoneKeys["ErrorCode"] = response[8:10]
    if TranslatedZoneKeys["ErrorCode"] == '00':
        TranslatedZoneKeys["KCV Processing Flag"] = response[10:11]
        TranslatedZoneKeys["ZPK(LMK)"] = response[11:44]
        TranslatedZoneKeys["ZPK Check Value"] = response[44:50]
        TranslatedZoneKeys["ZAK(LMK)"] = response[50:83]
        TranslatedZoneKeys["ZAK Check Value"] = response[83:89]
        TranslatedZoneKeys["ZEK(LMK)"] = response[89:122]
        TranslatedZoneKeys["ZEK Check Value"] = response[122:128]
    return  TranslatedZoneKeys

def Import_Public_Key(Key):
    result = KeyClass.execute_Import_Public_Key(Key)
    ResultMAC = {}
    ResultMAC["Header"] = result[2:6]
    ResultMAC["ResponseCode"] = result[6:8]
    ResultMAC["ErrorCode"] = result[8:10]
    if ResultMAC["ErrorCode"] == '00':
        ResultMAC["MAC"] = result[10:14]
        ResultMAC["Public_Key_LMK"] = result[14:]
    return ResultMAC

def Encrypt_a_Cross_Acquirer_Key_Encrypting_Key_under_an_Initial_Transport_Key(Mac, Pinpad_Public_Key, Secret_Key, Secrect_Key_Leghth,  DataBlock, RandomNumber):
    result = KeyClass.execute_Encrypt_a_Cross_Acquirer_Key_Encrypting_Key_under_an_Initial_Transport_Key(Mac, Pinpad_Public_Key, Secret_Key,Secrect_Key_Leghth, DataBlock, RandomNumber)
    ResultKCA = {}
    ResultKCA["Header"] = result[2:6]
    ResultKCA["ResponseCode"] = result[6:8]
    ResultKCA["ErrorCode"] = result[8:10]
    if ResultKCA["ErrorCode"] == '00':
        ResultKCA["KCA(KTI)"] = result[10:43]
        ResultKCA["KCA(LMK)"] = result[43:76]
        ResultKCA["DTS"] = result[76:88]
        ResultKCA["PPSN"] = result[88:104]
    return ResultKCA

def CalculateMAC_ZAK(Message, MAC_Key):
    responseMAC = KeyClass.execute_GenerateMAC(Message, MAC_Key)
    print responseMAC
    ResponseMAC = {}
    ResponseMAC["Header"] = responseMAC[2:6]
    ResponseMAC["ResponseCode"] = responseMAC[6:8]
    ResponseMAC["ErrorCode"] = responseMAC[8:10]
    if ResponseMAC["ErrorCode"] == '00':
        ResponseMAC["MAC"] = responseMAC[10:]
        return ResponseMAC

def BinaryDump(s):
    """
    Returns a hexdump in postilion trace format. It also removes the leading tcp length indicator

    0000(0000)  30 32 31 30 F2 3E 44 94  2F E0 84 20 00 00 00 00   0210.>D./.. ....
    0016(0010)  04 00 00 22 31 36 2A 2A  2A 2A 2A 2A 2A 2A 2A 2A   ..."16**********
    0032(0020)  2A 2A 2A 2A 2A 2A 30 31  31 30 30 30 30 30 30 30   ******0110000000
    0048(0030)  30 30 30 35 30 30 30 30  31 30 30 34 30 36 34 30   0005000010040640
    ...
    0576(0240)  36 3C 2F 44 61 74 61 3E  3C 2F 52 65 74 72 69 65   6</Data></Retrie
    0592(0250)  76 61 6C 52 65 66 4E 72  3E 3C 2F 42 61 73 65 32   valRefNr></Base2
    0608(0260)  34 44 61 74 61 3E								  4Data>
    """
    #Remove TCP length indicator
    s = s[2:]
    while s != '':
        part = s[:16]
        s = s[16:]

def ReadableAscii(s):
    """
    Print readable ascii string, non-readable characters are printed as periods (.)
    """
    r = ''
    for c in s:
        if ord(c) >= 32 and ord(c) <= 126:
            r += c
        else:
            r += '.'
    return r

def __PAN_2_UBCD(PAN):
        res = "\0" * 4
        for i in range(-13, -1):
            ch = PAN[i]
            res += chr(ord(ch) - ord('0'))
        return res

def dumphex(s):
  global i
  hex_str = 'Binary Data: \n'

  str = ""
  for i in range(0,len(s)):
    if s[i] in string.whitespace:
      str += '.'
      continue
    if s[i] in string.printable:
      str = str + s[i]
      continue
    str += '.'
  bytes = map(lambda x: '%.2x' % x, map(ord, s))
  print
  for i in xrange(0,len(bytes)/16):
    hex_str +=  '    %s' % string.join(bytes[i * 16:(i + 1) * 16])
    hex_str +=  '    %s\n' % str[i*16:(i+1)*16]
  hex_str += '    %-51s' % string.join(bytes[(i + 1) * 16:])
  hex_str += '%s\n' % str[(i+1)*16:]

  return hex_str.upper()



#Data =  GenerateKeys_Public_Private_Key_Pair()
#print ByteToHex(Data['Data'])
