"""

(C) Copyright 2012 Vyatcheslav E. Boyko

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

__author__ = 'Vyatcheslav Boyko <vboyko@tr-sys.com>'
__version__ = '1.0'
__licence__ = 'GPL V3'

from SPDHErrors import *
import struct


class SPDH:
    """Main Class to work with ISO8583 packages.
    Used to create, change, send, receive, parse or work with ISO8593 Package version 1993.
    It's 100% Python :)
    Enjoy it!
    Thanks to: Vulcanno IT Solutions <http://www.vulcanno.com.br>
    Licence: GPL Version 3
    More information: http://code.google.com/p/iso8583py/

    Example:
        from ISO8583.ISO8583 import ISO8583
        from ISO8583.ISOErrors import *

        iso = ISO8583()
        try:
            iso.setMTI('0800')
            iso.setBit(2,2)
            iso.setBit(4,4)
            iso.setBit(12,12)
            iso.setBit(21,21)
            iso.setBit(17,17)
            iso.setBit(49,986)
            iso.setBit(99,99)
        except ValueTooLarge, e:
                print ('Value too large :( %s' % e)
        except InvalidMTI, i:
                print ('This MTI is wrong :( %s' % i)

        print ('The Message Type Indication is = %s' %iso.getMTI())

        print ('The Bitmap is = %s' %iso.getBitmap())
        iso.showIsoBits();
        print ('This is the ISO8583 complete package %s' % iso.getRawIso())
        print ('This is the ISO8583 complete package to sent over the TCPIP network %s' % iso.getNetworkISO())

"""

    _BIT_DEFAULT_VALUE = None

    # SPDH contants
    _BITS_VALUE_TYPE = {}
    # Every _BITS_VALUE_TYPE has:
    # _BITS_VALUE_TYPE[N] = [ X,Y, Z, W,K]
    # N = bitnumber
    # X = smallStr representation of the bit meanning
    # Y = large str representation
    # Z = type of the bit (B, N, A, AN, ANS, LL, LLL)
    #W = size of the information that N need to has
    # K = type os values a, an, n, ansb, b
    _BITS_VALUE_TYPE['A'] = ['A', 'Customer Billing Address', 1, 20]
    _BITS_VALUE_TYPE['B'] = ['B', 'Amount1', 1, 18]
    _BITS_VALUE_TYPE['C'] = ['C', 'Amount2', 1, 18]
    _BITS_VALUE_TYPE['D'] = ['D', 'Application Account Type', 1, -1]
    _BITS_VALUE_TYPE['E'] = ['E', 'Application Account Number', 1, 19]
    _BITS_VALUE_TYPE['F'] = ['F', 'Approval Code', 8, -1]
    _BITS_VALUE_TYPE['G'] = ['G', 'Authentication Code', 8, -1]
    _BITS_VALUE_TYPE['H'] = ['H', 'Authentication Key', 16, 74]
    _BITS_VALUE_TYPE['I'] = ['I', 'Data Encryption Key', 16, -1]
    _BITS_VALUE_TYPE['J'] = ['J', 'Available Balance', 18, -1]
    _BITS_VALUE_TYPE['K'] = ['K', 'Business Date', 6, -1]
    _BITS_VALUE_TYPE['L'] = ['L', 'Check Type', 1, -1]
    _BITS_VALUE_TYPE['M'] = ['M', 'Communications Key', 16, 74]
    _BITS_VALUE_TYPE['N'] = ['N', 'Customer ID', 1, 40]
    _BITS_VALUE_TYPE['O'] = ['O', 'Customer ID Type', 2, -1]
    _BITS_VALUE_TYPE['P'] = ['P', 'Draft Capture Flag', 1, -1]
    _BITS_VALUE_TYPE['Q'] = ['Q', 'Echo Data', 1, 16]
    _BITS_VALUE_TYPE['R'] = ['R', 'Card Type', 1, -1]
    _BITS_VALUE_TYPE['S'] = ['S', 'Invoice Number', 1, 10]
    _BITS_VALUE_TYPE['T'] = ['T', 'Invoice Number/Original', 1, 10]
    _BITS_VALUE_TYPE['U'] = ['U', 'Language Code', 1, -1]
    _BITS_VALUE_TYPE['V'] = ['V', 'Mail/Download Key', 15, -1]
    _BITS_VALUE_TYPE['W'] = ['W', 'Mail Text/Download Data', 1, 957]
    _BITS_VALUE_TYPE['X'] = ['X', 'ISO Response Code', 3, -1]
    _BITS_VALUE_TYPE['Y'] = ['Y', 'Customer ZIP Code', 1, 9]
    _BITS_VALUE_TYPE['Z'] = ['Z', 'Address Verification Status Code', 1, -1]
    _BITS_VALUE_TYPE['a'] = ['a', 'Optional Data', 1, 250]
    _BITS_VALUE_TYPE['b'] = ['b', 'PIN/Customer', 16, -1]
    _BITS_VALUE_TYPE['c'] = ['c', 'PIN/Supervisor', 16, -1]
    _BITS_VALUE_TYPE['d'] = ['d', 'Retailer ID', 1, 12]
    _BITS_VALUE_TYPE['e'] = ['e', 'POS Condition Code', 2, -1]
    _BITS_VALUE_TYPE['f'] = ['f', 'PIN Length or Receipt Data', 1, 200]
    _BITS_VALUE_TYPE['g'] = ['g', 'Response Display', 1, 48]
    _BITS_VALUE_TYPE['h'] = ['h', 'Sequence Number', 10, -1]
    _BITS_VALUE_TYPE['i'] = ['i', 'Sequence Number/Original', 9, -1]
    _BITS_VALUE_TYPE['j'] = ['j', 'State Code', 2, -1]
    _BITS_VALUE_TYPE['k'] = ['k', 'Birth Date/Terminal Location', 0, 25]
    _BITS_VALUE_TYPE['l'] = ['l', 'Totals/Batch', 75, -1]
    _BITS_VALUE_TYPE['m'] = ['m', 'Totals/Day', 75, -1]
    _BITS_VALUE_TYPE['n'] = ['n', 'Totals/Employee', 75, -1]
    _BITS_VALUE_TYPE['o'] = ['o', 'Totals/Shift', 75, -1]
    _BITS_VALUE_TYPE['q'] = ['q', 'Track 2/Customer', 1, 40]
    _BITS_VALUE_TYPE['r'] = ['r', 'Track 2/Supervisor', 1, 40]
    _BITS_VALUE_TYPE['s'] = ['s', 'Transaction Description', 1, 24]
    _BITS_VALUE_TYPE['t'] = ['t', 'PIN Pad Identifier', 16, -1]
    _BITS_VALUE_TYPE['u'] = ['u', 'Acceptor Posting Date', 6, -1]
    _BITS_VALUE_TYPE['0'] = ['0', 'American Express Data Collection', 46, 118]
    _BITS_VALUE_TYPE['1'] = ['1', 'PS2000 Data', 24, -1]
    _BITS_VALUE_TYPE['2'] = ['2', 'Track 1/Customer', 1, 82]
    _BITS_VALUE_TYPE['3'] = ['3', 'Track 1/Supervisor', -1, 82]
    _BITS_VALUE_TYPE['4'] = ['4', 'Industry Data', 156, 171]
    _BITS_VALUE_TYPE['6'] = ['6', 'Product SubFIDs', 1, 1043]
    _BITS_VALUE_TYPE['7'] = ['7', 'Product SubFIDs', 1, 50]
    _BITS_VALUE_TYPE['8'] = ['8', 'Product SubFIDs', 1, 50]
    _BITS_VALUE_TYPE['9'] = ['9', 'Customer SubFIDs', 1, 50]

    _BIT_SUBFIDS_6 = {}
    _BIT_SUBFIDS_6['A'] = ['A', 'Host original data', 12, -1]
    _BIT_SUBFIDS_6['B'] = ['B', 'Manual CVD - customer', 4, -1]
    _BIT_SUBFIDS_6['C'] = ['C', 'Manual CVD - administrative', 4, -1]
    _BIT_SUBFIDS_6['D'] = ['D', 'Purchasing card/fleet card data', 30, 876]
    _BIT_SUBFIDS_6['E'] = ['E', 'POS entry mode', 3, -1]
    _BIT_SUBFIDS_6['F'] = ['F', 'Electronic commerce data', 1, 2]
    _BIT_SUBFIDS_6['G'] = ['G', 'Visa card type indicator', 1, -1]
    _BIT_SUBFIDS_6['H'] = ['H', 'CVD indicator and CVD result', 2, -1]
    _BIT_SUBFIDS_6['I'] = ['I', 'Transaction currency code', 3, -1]
    _BIT_SUBFIDS_6['J'] = ['J', 'Cardholder certificate SN', 32, -1]
    _BIT_SUBFIDS_6['K'] = ['K', 'Merchant certificate SN', 32, -1]
    _BIT_SUBFIDS_6['L'] = ['L', 'XID/trans stain', 80, -1]
    _BIT_SUBFIDS_6['N'] = ['N', 'Reason online code', 4, -1]
    _BIT_SUBFIDS_6['O'] = ['O', 'EMV request data', -1, 136]
    _BIT_SUBFIDS_6['P'] = ['P', 'EMV additional request data', -1, 64]
    _BIT_SUBFIDS_6['Q'] = ['Q', 'EMV response data', -1, 64]
    _BIT_SUBFIDS_6['R'] = ['R', 'EMV additional response data', -1, 258]
    _BIT_SUBFIDS_6['S'] = ['S', 'Stored value data', 63, -1]
    _BIT_SUBFIDS_6['T'] = ['T', 'Key SN and descriptor', 23, -1]
    _BIT_SUBFIDS_6['U'] = ['U', 'Transaction subtype data', 16, -1]
    _BIT_SUBFIDS_6['V'] = ['V', 'Auth. collection indicator', 1, -1]
    _BIT_SUBFIDS_6['W'] = ['W', 'CAVV/AAV result code', 1, -1]
    _BIT_SUBFIDS_6['X'] = ['X', 'Point of service data', 6, -1]
    _BIT_SUBFIDS_6['Y'] = ['Y', 'Authentication data', 2, 202]
    _BIT_SUBFIDS_6['Z'] = ['Z', 'Card verification flag 2', 1, -1]
    _BIT_SUBFIDS_6['b'] = ['b', 'Check conversion data', 39, -1]
    _BIT_SUBFIDS_6['c'] = ['c', 'MICR data', 64, -1]
    _BIT_SUBFIDS_6['d'] = ['d', 'Check callback information', 115, -1]
    _BIT_SUBFIDS_6['e'] = ['e', 'Interchange compliance data', 21, -1]
    _BIT_SUBFIDS_6['f'] = ['f', 'Response source/reason code', 1, -1]
    _BIT_SUBFIDS_6['g'] = ['g', 'POS merchant data', 4, -1]
    _BIT_SUBFIDS_6['h'] = ['h', 'STAN', 6, -1]
    _BIT_SUBFIDS_6['i'] = ['i', 'Retrieval Reference Number', 12, -1]
    _BIT_SUBFIDS_6['j'] = ['j', 'Debit Network/Sharing Group ID', 4, -1]
    _BIT_SUBFIDS_6['k'] = ['k', 'Card Level Results', 2, -1]
    _BIT_SUBFIDS_6['l'] = ['l', 'Healthcare/Transit Data', 20, 120]
    _BIT_SUBFIDS_6['m'] = ['m', 'Healthcare Service Data', 19, 95]
    _BIT_SUBFIDS_6['n'] = ['n', 'Error Flag', 1, -1]
    _BIT_SUBFIDS_6['o'] = ['o', 'American Express Additional Data', 3, 300]

    _BIT_SUBFIDS_7 = {}
    _BIT_SUBFIDS_7['a'] = ['a', 'Mobile Top-Up Track 2', 1, 40]
    _BIT_SUBFIDS_7['b'] = ['b', 'Mobile Top-Up Reference Number', 15, -1]
    _BIT_SUBFIDS_7['c'] = ['c', 'Mobile Top-Up Response', 65, -1]

    _BIT_SUBFIDS_8 = {}
    _BIT_SUBFIDS_8['A'] = ['A', 'EBT Voucher Number', 18, 24]
    _BIT_SUBFIDS_8['B'] = ['B', 'EBT Available Balance', 18, -1]

    _BIT_SUBFIDS = {}
    _BIT_SUBFIDS['6'] = _BIT_SUBFIDS_6
    _BIT_SUBFIDS['7'] = _BIT_SUBFIDS_7
    _BIT_SUBFIDS['8'] = _BIT_SUBFIDS_8

    _HEADER_FIELDS = {}
    _HEADER_FIELDS[0] = ['Device Type', 'an', 2]
    _HEADER_FIELDS[1] = ['Transmission Number', 'n', 2]
    _HEADER_FIELDS[2] = ['Terminal ID', 'an', 16]
    _HEADER_FIELDS[3] = ['Employee ID', 'an', 6]
    _HEADER_FIELDS[4] = ['Current Date', 'n', 6]
    _HEADER_FIELDS[5] = ['Current Time', 'n', 6]
    _HEADER_FIELDS[6] = ['Message Type', 'an', 1]
    _HEADER_FIELDS[7] = ['Message Subtype', 'an', 1]
    _HEADER_FIELDS[8] = ['Transaction Code', 'n', 2]
    _HEADER_FIELDS[9] = ['Processing Flag 1', 'n', 1]
    _HEADER_FIELDS[10] = ['Processing Flag 2', 'n', 1]
    _HEADER_FIELDS[11] = ['Processing Flag 3', 'n', 1]
    _HEADER_FIELDS[12] = ['Response Code', 'n', 3]

    _HEADER_LEN = 48

    _FIELD_SEPARATOR = '\x1c'
    _SUBFIELD_SEPARATOR = '\x1e'

    _STX = '\x02'
    _ETX = '\x03'

    ################################################################################################
    #Default constructor of the SPDH Object
    def __init__(self, iso="", use_tpdu=True, debug=False):
        """Default Constructor of SPDH Package.
        It inicialize a "brand new" SPDH package
        Example: To Enable debug you can use:
            pack = SPDH(debug=True)
        @param: iso a String that represents the ASCII of the package. The same that you need to pass to setContent() method.
        @param: debug (True or False) default False -> Used to print some debug infos. Only use if want that messages!
        """
        #Values
        self.FIELDS_VALUES = {}
        self.SUBFL6_VALUES = {}
        self.SUBFL7_VALUES = {}
        self.SUBFL8_VALUES = {}

        self.SUBFLD_VALUES = {}
        self.SUBFLD_VALUES['6'] = self.SUBFL6_VALUES
        self.SUBFLD_VALUES['7'] = self.SUBFL7_VALUES
        self.SUBFLD_VALUES['8'] = self.SUBFL8_VALUES

        self.HEADER_VALUES = []

        #Bitmap ASCII representantion
        # MTI
        self.MESSAGE_TYPE_INDICATION = ''
        #Debug ?
        self.DEBUG = debug
        # Initialise header
        self.use_tpdu = use_tpdu

        self.raw_binary = True

        # initialize values
        self.__initializeHeaderValues()

        if iso != "":
            self.setContent(iso)

    def __getCleanHeaderValue(self, bit, val):
        type = self._HEADER_FIELDS[bit][1]
        l = self._HEADER_FIELDS[bit][2]
        if ( val != None and len(val) > l ):
            raise ValueTooLarge('Invalid length of header \'%r\' value. Given length: %d' % ( bit, len(val), ))
        if type == 'an':
            if val == None:
                return ' ' * l
            else:
                return val.ljust(l)
        elif type == 'n':
            if val == None:
                return '0' * l
            else:
                return '0' * ( l - len(val) ) + val

    def __initializeHeaderValues(self):
        if self.DEBUG == True:
            print ('Init header values')

        count = len(self._HEADER_FIELDS)
        if len(self.HEADER_VALUES) == count:
            for cont in xrange(0, count):
                self.HEADER_VALUES[cont] = self.__getCleanHeaderValue(cont, None)
        else:
            for cont in xrange(0, count):
                self.HEADER_VALUES.append(self.__getCleanHeaderValue(cont, None))

    def __checkLength(self, min, max, len):
        # undefined max len
        if ( max == -1 ):
            return min == len
        # undefined min len
        if ( min == -1 ):
            return max >= len
        return min <= len <= max

    def getHeaderLen(self, bit):
        return self._HEADER_FIELDS[bit][2]

    def getHeaderValue(self, bit):
        return self.HEADER_VALUES[bit]

    def getHeaderName(self, bit):
        return self._HEADER_FIELDS[bit][0]

    def __decodeHeader(self, tail):
        if ( self._HEADER_LEN != len(tail) ):
            raise InvalidHeader('Invalid header length')

        for h in self._HEADER_FIELDS:
            l = self.getHeaderLen(h)
            head, tail = tail[:l], tail[l:]
            self.HEADER_VALUES[h] = head
        if ( self.DEBUG ):
            for h in self._HEADER_FIELDS:
                print "%04d %-22s: %r" % ( h, self.getHeaderName(h), self.getHeaderValue(h), )

    def __saveBit(self, defs, vals, bit, value):
        if ( bit not in defs ):
            raise BitInexistent('Bit %r doesn\'t exist in this specification' % (bit,))
        min = defs[bit][2]
        max = defs[bit][3]
        if ( self.__checkLength(min, max, len(value)) == False ):
            raise InvalidValueLen('Bit %r has invalid length. It should be ' \
                                  'in range(%d,%d) but found %d bytes' % ( bit, min, max, len(value), ))
        vals[bit] = value

    def __parseSPDH(self, data, defs, vals, separator):
        start = stop = 0
        bit = None
        for i in xrange(0, len(data)):
            if data[i] != separator:
                continue
            if bit != None:
                self.__saveBit(defs, vals, bit, data[start:i])
            bit, start = data[i + 1], i + 2
        # save last bit
        if ( bit != None ):
            self.__saveBit(defs, vals, bit, data[start:])
        if ( self.DEBUG == True ):
            for v in vals:
                print "%-4s %-25s len=%d: %r" % ( v, defs[v][1], len(vals[v]), vals[v], )

    def __decodeFields(self, data):
        if ( self.DEBUG == True ):
            print '\nOptional data fields'
        self.__parseSPDH(data, self._BITS_VALUE_TYPE, self.FIELDS_VALUES, self._FIELD_SEPARATOR)

        for bit in self._BIT_SUBFIDS:
            if bit in self.FIELDS_VALUES:
                if ( self.DEBUG == True ):
                    print '\nProduct %s SubFIDs:' % ( bit, )
                self.__parseSPDH(data, self._BIT_SUBFIDS[bit], self.SUBFLD_VALUES[bit], self._SUBFIELD_SEPARATOR)

    def getContent(self):
        outbin = self._STX

        for bit in xrange(0, len(self.HEADER_VALUES)):
            print self.HEADER_VALUES[bit]
            outbin += self.__getCleanHeaderValue(bit, self.HEADER_VALUES[bit])
        for bit in self._BITS_VALUE_TYPE:
            if bit in self.FIELDS_VALUES:
                if bit not in self._BIT_SUBFIDS:
                    outbin += self._FIELD_SEPARATOR
                    outbin += bit
                    outbin += self.FIELDS_VALUES[bit]
        for fid in self._BIT_SUBFIDS:
            if fid in self.FIELDS_VALUES:
                outbin += self._FIELD_SEPARATOR
                outbin += fid
                for subfid in self._BIT_SUBFIDS[fid]:
                    if subfid in self.SUBFLD_VALUES[fid]:
                        outbin += self._SUBFIELD_SEPARATOR
                        outbin += subfid
                        outbin += self.SUBFLD_VALUES[fid][subfid]
        outbin += self._ETX
        return outbin

    ################################################################################################
    #Return bit type
    def getBitType(self, bit):
        """Method that return the bit Type
        @param: bit -> Bit that will be searched and whose type will be returned
        @return: str that represents the type of the bit
        """
        return self._BITS_VALUE_TYPE[bit][2]

    ################################################################################################

    ################################################################################################
    #Return bit limit
    def getBitLimit(self, bit):
        """Method that return the bit limit (Max size)
        @param: bit -> Bit that will be searched and whose limit will be returned
        @return: int that indicate the limit of the bit
        """
        return self._BITS_VALUE_TYPE[bit][3]

    ################################################################################################

    ################################################################################################
    #Return bit value type
    def getBitValueType(self, bit):
        """Method that return the bit value type
        @param: bit -> Bit that will be searched and whose value type will be returned
        @return: str that indicate the valuye type of the bit
        """
        return self._BITS_VALUE_TYPE[bit][4]

    ################################################################################################

    ################################################################################################
    #Return large bit name
    def getLargeBitName(self, bit):
        """Method that return the large bit name
        @param: bit -> Bit that will be searched and whose name will be returned
        @return: str that represents the name of the bit
        """
        return self._BITS_VALUE_TYPE[bit][1]

    ################################################################################################
    # Set the MTI
    def setTransationType(self, type):
        """Method that set Transation Type (MTI)
        @param: type -> MTI to be setted
        @raise: ValueTooLarge Exception
        """

        type = "%s" % type
        if len(type) > 4:
            type = type[0:3]
            raise ValueTooLarge('Error: value up to size! MTI limit size = 4')

        typeT = "";
        if len(type) < 4:
            for cont in range(len(type), 4):
                typeT += "0"

        self.MESSAGE_TYPE_INDICATION = "%s%s" % (typeT, type)

    ################################################################################################

    ################################################################################################
    # setMTI too
    def setMTI(self, type):
        """Method that set Transation Type (MTI)
        In fact, is an alias to "setTransationType" method
        @param: type -> MTI to be setted
        """
        self.setTransationType(type)

    ################################################################################################
    # Set a value to a bit
    def setBit(self, bit, value):
        """Method used to set a bit with a value.
        It's one of the most important method to use when using this library
        @param: bit -> bit number that want to be setted
        @param: value -> the value of the bit
        @return: True/False default True -> To be used in the future!
        @raise: BitInexistent Exception, ValueTooLarge Exception
        """
        if self.DEBUG == True:
            print ('Setting bit inside bitmap bit[%s] = %s') % (bit, value)

        if bit < 1 or bit > 128:
            raise BitInexistent("Bit number %s dosen't exist!" % bit)

        # caculate the position insede bitmap
        pos = 1

        if self.getBitType(bit) == 'LL':
            self.__setBitTypeLL(bit, value)

        if self.getBitType(bit) == 'LLL':
            self.__setBitTypeLLL(bit, value)

        if self.getBitType(bit) == 'N':
            self.__setBitTypeN(bit, value)

        if self.getBitType(bit) == 'A':
            self.__setBitTypeA(bit, value)

        if self.getBitType(bit) == 'ANS' or self.getBitType(bit) == 'B':
            self.__setBitTypeANS(bit, value)

        if self.getBitType(bit) == 'B':
            self.__setBitTypeB(bit, value)



        #Continuation bit?
        if bit > 64:
            self.BITMAP[0] = self.BITMAP[0] | self._TMP[2]  # need to set bit 1 of first "bit" in bitmap

        if (bit % 8) == 0:
            pos = (bit / 8) - 1
        else:
            pos = (bit / 8)

        #need to check if the value can be there .. AN , N ... etc ... and the size

        self.BITMAP[pos] = self.BITMAP[pos] | self._TMP[(bit % 8) + 1]

        return True

    ################################################################################################
    #return a array of bits, when processing the bitmap
    def __getBitsFromBitmap(self):
        """Method that process the bitmap and return a array with the bits presents inside it.
        It's a internal method, so don't call!
        """
        bits = []
        for c in range(0, 16):
            for d in range(1, 9):
                if self.DEBUG == True:
                    print (
                    'Value (%d)-> %s & %s = %s' % (d, self.BITMAP[c], self._TMP[d], (self.BITMAP[c] & self._TMP[d]) ))
                if (self.BITMAP[c] & self._TMP[d]) == self._TMP[d]:
                    if d == 1:  #  e o 8 bit
                        if self.DEBUG == True:
                            print ('Bit %s is present !!!' % ((c + 1) * 8))

                        bits.append((c + 1) * 8)
                    else:
                        if (c == 0) & (d == 2):  # Continuation bit
                            if self.DEBUG == True:
                                print ('Bit 1 is present !!!')

                            bits.append(1)

                        else:
                            if self.DEBUG == True:
                                print ('Bit %s is present !!!' % (c * 8 + d - 1))

                            bits.append(c * 8 + d - 1)

        bits.sort()

        return bits

    ################################################################################################

    ################################################################################################
    #Set of type LL
    def __setBitTypeLL(self, bit, value):
        """Method that set a bit with value in form LL
        It put the size in front of the value
        Example: pack.setBit(99,'123') -> Bit 99 is a LL type, so this bit, in ASCII form need to be 03123. To understand, 03 is the size of the information and 123 is the information/value
        @param: bit -> bit to be setted
        @param: value -> value to be setted
        @raise: ValueTooLarge Exception
        It's a internal method, so don't call!
        """

        value = "%s" % value

        if len(value) > 99:
            #value = value[0:99]
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))
        if len(value) > self.getBitLimit(bit):
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))

        size = "%s" % len(value)

        self.BITMAP_VALUES[bit] = "%s%s" % ( size.zfill(2), value)

    ################################################################################################

    ################################################################################################
    #Set of type LLL
    def __setBitTypeLLL(self, bit, value):
        """Method that set a bit with value in form LLL
        It put the size in front of the value
        Example: pack.setBit(104,'12345ABCD67890') -> Bit 104 is a LLL type, so this bit, in ASCII form need to be 01412345ABCD67890.
            To understand, 014 is the size of the information and 12345ABCD67890 is the information/value
        @param: bit -> bit to be setted
        @param: value -> value to be setted
        @raise: ValueTooLarge Exception
        It's a internal method, so don't call!
        """

        value = "%s" % value

        if len(value) > 999:
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))
        if len(value) > self.getBitLimit(bit):
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))

        size = "%s" % len(value)

        self.BITMAP_VALUES[bit] = "%s%s" % ( size.zfill(3), value)

    ################################################################################################

    ################################################################################################
    # Set of type N,
    def __setBitTypeN(self, bit, value):
        """Method that set a bit with value in form N
        It complete the size of the bit with a default value
        Example: pack.setBit(3,'30000') -> Bit 3 is a N type, so this bit, in ASCII form need to has size = 6 (ISO especification) so the value 30000 size = 5 need to receive more "1" number.
            In this case, will be "0" in the left. In the package, the bit will be sent like '030000'
        @param: bit -> bit to be setted
        @param: value -> value to be setted
        @raise: ValueTooLarge Exception
        It's a internal method, so don't call!
        """

        value = "%s" % value

        if len(value) > self.getBitLimit(bit):
            value = value[0:self.getBitLimit(bit)]
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))

        self.BITMAP_VALUES[bit] = value.zfill(self.getBitLimit(bit))

    ################################################################################################

    ################################################################################################
    # Set of type A
    def __setBitTypeA(self, bit, value):
        """Method that set a bit with value in form A
        It complete the size of the bit with a default value
        Example: pack.setBit(3,'30000') -> Bit 3 is a A type, so this bit, in ASCII form need to has size = 6 (ISO especification) so the value 30000 size = 5 need to receive more "1" number.
            In this case, will be "0" in the left. In the package, the bit will be sent like '030000'
        @param: bit -> bit to be setted
        @param: value -> value to be setted
        @raise: ValueTooLarge Exception
        It's a internal method, so don't call!
        """

        value = "%s" % value

        if len(value) > self.getBitLimit(bit):
            value = value[0:self.getBitLimit(bit)]
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))

        self.BITMAP_VALUES[bit] = value.zfill(self.getBitLimit(bit))

    ################################################################################################

    ################################################################################################
    # Set of type B
    def __setBitTypeB(self, bit, value):
        """Method that set a bit with value in form B
        It complete the size of the bit with a default value
        Example: pack.setBit(3,'30000') -> Bit 3 is a B type, so this bit, in ASCII form need to has size = 6 (ISO especification) so the value 30000 size = 5 need to receive more "1" number.
            In this case, will be "0" in the left. In the package, the bit will be sent like '030000'
        @param: bit -> bit to be setted
        @param: value -> value to be setted
        @raise: ValueTooLarge Exception
        It's a internal method, so don't call!
        """

        value = "%s" % value

        if len(value) > self.getBitLimit(bit):
            value = value[0:self.getBitLimit(bit)]
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))

        self.BITMAP_VALUES[bit] = value.zfill(self.getBitLimit(bit))

    ################################################################################################

    ################################################################################################
    # Set of type ANS
    def __setBitTypeANS(self, bit, value):
        """Method that set a bit with value in form ANS
        It complete the size of the bit with a default value
        Example: pack.setBit(3,'30000') -> Bit 3 is a ANS type, so this bit, in ASCII form need to has size = 6 (ISO especification) so the value 30000 size = 5 need to receive more "1" number.
            In this case, will be "0" in the left. In the package, the bit will be sent like '030000'
        @param: bit -> bit to be setted
        @param: value -> value to be setted
        @raise: ValueTooLarge Exception
        It's a internal method, so don't call!
        """

        value = "%s" % value

        if len(value) > self.getBitLimit(bit):
            value = value[0:self.getBitLimit(bit)]
            raise ValueTooLarge('Error: value up to size! Bit[%s] of type %s limit size = %s' % (
            bit, self.getBitType(bit), self.getBitLimit(bit)))

        self.BITMAP_VALUES[bit] = value.zfill(self.getBitLimit(bit))

    ################################################################################################

    ################################################################################################
    # print os bits insede iso
    def showIsoBits(self):
        """Method that show in detail a list of bits , values and types inside the object
        Example: output to
            (...)
            iso.setBit(2,2)
            iso.setBit(4,4)
            (...)
            iso.showIsoBits()
            (...)
            Bit[2] of type LL has limit 19 = 012
            Bit[4] of type N has limit 12 = 000000000004
            (...)
        """

        for cont in range(0, 128):
            if self.BITMAP_VALUES[cont] != self._BIT_DEFAULT_VALUE:
                print("Bit[%s] of type %s has limit %s = %s" % (
                cont, self.getBitType(cont), self.getBitLimit(cont), self.BITMAP_VALUES[cont]) )


    ################################################################################################

    ################################################################################################
    # print Raw iso
    def showRawIso(self):
        """Method that print ISO8583 ASCII complete representation
        Example:
        iso = ISO8583()
        iso.setMTI('0800')
        iso.setBit(2,2)
        iso.setBit(4,4)
        iso.setBit(12,12)
        iso.setBit(17,17)
        iso.setBit(99,99)
        iso.showRawIso()
        output (print) -> 0800d010800000000000000000002000000001200000000000400001200170299
        Hint: Try to use getRawIso method and format your own print :)
        """

        resp = self.getRawIso()
        print resp


    ################################################################################################

    ################################################################################################
    # Return raw iso
    def getRawIso(self):
        """Method that return ISO8583 ASCII complete representation
        Example:
        iso = ISO8583()
        iso.setMTI('0800')
        iso.setBit(2,2)
        iso.setBit(4,4)
        iso.setBit(12,12)
        iso.setBit(17,17)
        iso.setBit(99,99)
        str = iso.getRawIso()
        print ('This is the ASCII package %s' % str)
        output (print) -> This is the ASCII package 0800d010800000000000000000002000000001200000000000400001200170299

        @return: str with complete ASCII ISO8583
        @raise: InvalidMTI Exception
        """

        self.__buildBitmap()

        if self.MESSAGE_TYPE_INDICATION == '':
            raise InvalidMTI('Check MTI! Do you set it?')

        resp = "";

        resp += self.MESSAGE_TYPE_INDICATION
        resp += self.BITMAP_HEX

        for cont in range(0, 128):
            if self.BITMAP_VALUES[cont] != self._BIT_DEFAULT_VALUE:
                resp = "%s%s" % (resp, self.BITMAP_VALUES[cont])

        return resp


    ################################################################################################

    ################################################################################################
    #Redefine a bit
    def redefineBit(self, bit, smallStr, largeStr, bitType, size, valueType):
        """Method that redefine a bit structure in global scope!
        Can be used to personalize ISO8583 structure to another specification (ISO8583 1987 for example!)
        Hint: If you have a lot of "ValueTooLarge Exception" maybe the especification that you are using is different of mine. So you will need to use this method :)
        @param: bit -> bit to be redefined
        @param: smallStr -> a small String representantion of the bit, used to build "user friendly prints", example "2" for bit 2
        @param: largeStr -> a large String representantion of the bit, used to build "user friendly prints" and to be used to inform the "main use of the bit",
            example "Primary account number (PAN)" for bit 2
        @param: bitType -> type the bit, used to build the values, example "LL" for bit 2. Need to be one of (B, N, AN, ANS, LL, LLL)
        @param: size -> limit size the bit, used to build/complete the values, example "19" for bit 2.
        @param: valueType -> value type the bit, used to "validate" the values, example "n" for bit 2. This mean that in bit 2 we need to have only numeric values.
            Need to be one of (a, an, n, ansb, b)
        @raise: BitInexistent Exception, InvalidValueType Exception

        """

        if self.DEBUG == True:
            print ('Trying to redefine the bit with (self,%s,%s,%s,%s,%s,%s)' % (
            bit, smallStr, largeStr, bitType, size, valueType))

        #validating bit position
        if bit == 1 or bit == 64 or bit < 0 or bit > 128:
            raise BitInexistent("Error %d cannot be changed because has a invalid number!" % bit)

        #need to validate if the type and size is compatible! example slimit = 100 and type = LL

        if bitType == "B" or bitType == "N" or bitType == "AN" or bitType == "ANS" or bitType == "LL" or bitType == "LLL":
            if valueType == "a" or valueType == "n" or valueType == "ansb" or valueType == "ans" or valueType == "b" or valueType == "an":
                self._BITS_VALUE_TYPE[bit] = [smallStr, largeStr, bitType, size, valueType]
                if self.DEBUG == True:
                    print ('Bit %d redefined!' % bit)

            else:
                raise InvalidValueType(
                    "Error bit %d cannot be changed because %s is not a valid valueType (a, an, n ansb, b)!" % (
                    bit, valueType))
            #return
        else:
            raise InvalidBitType(
                "Error bit %d cannot be changed because %s is not a valid bitType (Hex, N, AN, ANS, LL, LLL)!" % (
                bit, bitType))
        #return

    ################################################################################################

    ################################################################################################
    #a partir de um trem de string, pega o MTI
    def __setMTIFromStr(self, iso):
        """Method that get the first 4 characters to be the MTI.
        It's a internal method, so don't call!
        """

        self.MESSAGE_TYPE_INDICATION = iso[0:4]

        if self.DEBUG == True:
            print ('MTI found was %s' % self.MESSAGE_TYPE_INDICATION)


    ################################################################################################

    ################################################################################################
    #return the MTI
    def getMTI(self):
        """Method that return the MTI of the package
        @return: str -> with the MTI
        """

        #Need to validate if the MTI was setted ...etc ...
        return self.MESSAGE_TYPE_INDICATION


    ################################################################################################

    ################################################################################################
    #Return the bitmap
    def getBitmap(self):
        """Method that return the ASCII Bitmap of the package
        @return: str -> with the ASCII Bitmap
        """
        if self.BITMAP_HEX == '':
            self.__buildBitmap()

        return self.BITMAP_HEX


    ################################################################################################

    ################################################################################################
    #return the Varray of values
    def getValuesArray(self):
        """Method that return an internal array of the package
        @return: array -> with all bits, presents or not in the bitmap
        """
        return self.BITMAP_VALUES


    ################################################################################################

    ################################################################################################
    #Receive a str and interpret it to bits and values
    def __getBitFromStr(self, strWithoutMtiBitmap):
        """Method that receive a string (ASCII) without MTI and Bitmaps (first and second), understand it and remove the bits values
        @param: str -> with all bits presents whithout MTI and bitmap
        It's a internal method, so don't call!
        """

        if self.DEBUG == True:
            print ('This is the input string <%s>' % strWithoutMtiBitmap)

        offset = 0;
        # jump bit 1 because it was alread defined in the "__inicializeBitsFromBitmapStr"
        for cont in range(2, 128):
            if self.BITMAP_VALUES[cont] != self._BIT_DEFAULT_VALUE:
                if self.DEBUG == True:
                    print ('String = %s offset = %s bit = %s' % (strWithoutMtiBitmap[offset:], offset, cont))

                if self.getBitType(cont) == 'LL':
                    valueSize = int(strWithoutMtiBitmap[offset:offset + 2])
                    if self.DEBUG == True:
                        print ('Size of the message in LL = %s' % valueSize)

                    if valueSize > self.getBitLimit(cont):
                        raise ValueTooLarge("This bit is larger than the especification!")
                    self.BITMAP_VALUES[cont] = strWithoutMtiBitmap[offset:offset + 2] + strWithoutMtiBitmap[
                                                                                        offset + 2:offset + 2 + valueSize]

                    if self.DEBUG == True:
                        print ('\tSetting bit %s value %s' % (cont, self.BITMAP_VALUES[cont]))

                    offset += valueSize + 2

                if self.getBitType(cont) == 'LLL':
                    valueSize = int(strWithoutMtiBitmap[offset:offset + 3])
                    if self.DEBUG == True:
                        print ('Size of the message in LLL = %s' % valueSize)

                    if valueSize > self.getBitLimit(cont):
                        raise ValueTooLarge("This bit is larger than the especification!")
                    self.BITMAP_VALUES[cont] = strWithoutMtiBitmap[offset:offset + 3] + strWithoutMtiBitmap[
                                                                                        offset + 3:offset + 3 + valueSize]

                    if self.DEBUG == True:
                        print ('\tSetting bit %s value %s' % (cont, self.BITMAP_VALUES[cont]))

                    offset += valueSize + 3

                # if self.getBitType(cont) == 'LLLL':
                # valueSize = int(strWithoutMtiBitmap[offset:offset +4])
                # if valueSize > self.getBitLimit(cont):
                # raise ValueTooLarge("This bit is larger than the especification!")
                # self.BITMAP_VALUES[cont] = '(' + strWithoutMtiBitmap[offset:offset+4] + ')' + strWithoutMtiBitmap[offset+4:offset+4+valueSize]
                # offset += valueSize + 4

                if self.getBitType(cont) == 'N' or self.getBitType(cont) == 'A' or self.getBitType(
                        cont) == 'ANS' or self.getBitType(cont) == 'B' or self.getBitType(cont) == 'AN':
                    self.BITMAP_VALUES[cont] = strWithoutMtiBitmap[offset:self.getBitLimit(cont) + offset]

                    if self.DEBUG == True:
                        print ('\tSetting bit %s value %s' % (cont, self.BITMAP_VALUES[cont]))

                    offset += self.getBitLimit(cont)


    ################################################################################################

    ################################################################################################
    #Parse a ASCII iso to object
    def setContent(self, iso):

        #start, end = iso.find(self._STX), iso.find(self._ETX)

        #if ( start == -1 ):
        #    raise InvalidSPDH('There is no STX in the beginning')
        #if ( end == -1 ):
        #    raise InvalidSPDH('There is no ETX in the end')

        #iso = iso[start + 1:end]

        length = len(iso)

        #if length < self._HEADER_LEN:
        #    raise InvalidSPDH('This is not a valid spdh.')
        if self.DEBUG == True:
            print ('ASCII to process <%s>' % iso)

        self.__decodeHeader(iso[:self._HEADER_LEN])
        self.__decodeFields(iso[self._HEADER_LEN:])

    ################################################################################################

    ################################################################################################
    #Method that compare 2 isos
    def __cmp__(self, obj2):
        """Method that compare two objects in "==", "!=" and other things
        Example:
            p1 = ISO8583()
            p1.setMTI('0800')
            p1.setBit(2,2)
            p1.setBit(4,4)
            p1.setBit(12,12)
            p1.setBit(17,17)
            p1.setBit(99,99)

            #get the rawIso and save in the iso variable
            iso = p1.getRawIso()

            p2 = ISO8583()
            p2.setContent(iso)

            print 'Is equivalent?'
            if p1 == p1:
                print ('Yes :)')
            else:
                print ('Noooooooooo :(')

        @param: obj2 -> object that will be compared
        @return: <0 if is not equal, 0 if is equal
        """
        ret = -1  # By default is different
        if (self.getMTI() == obj2.getMTI()) and (self.getBitmap() == obj2.getBitmap()) and (
            self.getValuesArray() == obj2.getValuesArray()):
            ret = 0

        return ret

    ################################################################################################

    ################################################################################################
    # Method that return a array with bits and values inside the iso package
    def getBitsAndValues(self):
        """Method that return an array of bits, values, types etc.
            Each array value is a dictionary with: {'bit':X ,'type': Y, 'value': Z} Where:
                bit: is the bit number
                type: is the bit type
                value: is the bit value inside this object
            so the Generic array returned is:  [ (...),{'bit':X,'type': Y, 'value': Z}, (...)]

        Example:
            p1 = ISO8583()
            p1.setMTI('0800')
            p1.setBit(2,2)
            p1.setBit(4,4)
            p1.setBit(12,12)
            p1.setBit(17,17)
            p1.setBit(99,99)

            v1 = p1.getBitsAndValues()
            for v in v1:
                print ('Bit %s of type %s with value = %s' % (v['bit'],v['type'],v['value']))

        @return: array of values.
        """
        ret = []
        for cont in range(2, 128):
            if self.BITMAP_VALUES[cont] != self._BIT_DEFAULT_VALUE:
                _TMP = {}
                _TMP['bit'] = "%d" % cont
                _TMP['type'] = self.getBitType(cont)
                _TMP['value'] = self.BITMAP_VALUES[cont]
                ret.append(_TMP)
        return ret

    ################################################################################################

    ################################################################################################
    # Method that return a array with bits and values inside the iso package
    def getBit(self, bit):
        """Return the value of the bit
        @param: bit -> the number of the bit that you want the value
        @raise: BitInexistent Exception, BitNotSet Exception
        """

        if bit < 1 or bit > 128:
            raise BitInexistent("Bit number %s dosen't exist!" % bit)

        #Is that bit set?
        isThere = False
        arr = self.__getBitsFromBitmap()

        if self.DEBUG == True:
            print ('This is the array of bits inside the bitmap %s' % arr)

        for v in arr:
            if v == bit:
                value = self.BITMAP_VALUES[bit]
                isThere = True
                break

        if isThere:
            return value
        else:
            raise BitNotSet("Bit number %s was not set!" % bit)

    ################################################################################################

    ################################################################################################
    #Method that return ISO8583 to TCPIP network form, with the size in the beginning.
    def getNetworkISO(self, bigEndian=True):
        """Method that return ISO8583 ASCII package with the size in the beginning
        By default, it return the package with size represented with big-endian.
        Is the same that:
            import struct
            (...)
            iso = ISO8583()
            iso.setBit(3,'300000')
            (...)
            ascii = iso.getRawIso()
            # Example: big-endian
            # To little-endian, replace '!h' with '<h'
            netIso = struct.pack('!h',len(iso))
            netIso += ascii
            # Example: big-endian
            # To little-endian, replace 'iso.getNetworkISO()' with 'iso.getNetworkISO(False)'
            print ('This <%s> the same that <%s>' % (iso.getNetworkISO(),netIso))

        @param: bigEndian (True|False) -> if you want that the size be represented in this way.
        @return: size + ASCII ISO8583 package ready to go to the network!
        @raise: InvalidMTI Exception
        """

        netIso = ""
        asciiIso = self.getRawIso()

        if bigEndian:
            netIso = struct.pack('!h', len(asciiIso))
            if self.DEBUG == True:
                print ('Pack Big-endian')
        else:
            netIso = struct.pack('<h', len(asciiIso))
            if self.DEBUG == True:
                print ('Pack Little-endian')

        netIso += asciiIso

        return netIso

    ################################################################################################

    ################################################################################################
    # Method that recieve a ISO8583 ASCII package in the network form and parse it.
    def setNetworkISO(self, iso, bigEndian=True):
        """Method that receive sie + ASCII ISO8583 package and transfor it in the ISO8583 object.
            By default, it recieve the package with size represented with big-endian.
            Is the same that:
            import struct
            (...)
            iso = ISO8583()
            iso.setBit(3,'300000')
            (...)
            # Example: big-endian
            # To little-endian, replace 'iso.getNetworkISO()' with 'iso.getNetworkISO(False)'
            netIso = iso.getNetworkISO()
            newIso = ISO8583()
            # Example: big-endian
            # To little-endian, replace 'newIso.setNetworkISO()' with 'newIso.setNetworkISO(False)'
            newIso.setNetworkISO(netIso)
            #Is the same that:
            #size = netIso[0:2]
            ## To little-endian, replace '!h' with '<h'
            #size = struct.unpack('!h',size )
            #newIso.setContent(netIso[2:size])
            arr = newIso.getBitsAndValues()
            for v in arr:
                print ('Bit %s Type %s Value = %s' % (v['bit'],v['type'],v['value']))

            @param: iso -> str that represents size + ASCII ISO8583 package
            @param: bigEndian (True|False) -> Codification of the size.
            @raise: InvalidIso8583 Exception
        """

        if len(iso) < 24:
            raise InvalidSPDH('This is not a valid iso!!Invalid Size')

        size = iso[0:2]
        if bigEndian:
            size = struct.unpack('!h', size)
            if self.DEBUG == True:
                print ('Unpack Big-endian')
        else:
            size = struct.unpack('<h', size)
            if self.DEBUG == True:
                print ('Unpack Little-endian')

        if len(iso) != (size[0] + 2):
            raise InvalidSPDH(
                'This is not a valid iso!!The ISO8583 ASCII(%s) is less than the size %s!' % (len(iso[2:]), size[0]))

        self.setContent(iso[2:])

        ################################################################################################