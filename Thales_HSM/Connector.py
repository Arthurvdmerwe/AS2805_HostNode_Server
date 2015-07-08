__author__ = 'root'
import socket
import logging
import logging.handlers
from struct import *

import Config


class ThalesConnector(object):
    _iInstance = None
    class Singleton:
        def __init__(self):
            # add singleton variables here
            self.log = logging.getLogger('Thales')
            self.TCP_IP = Config.hsm_ip
            #self.TCP_IP = '203.213.124.34'
            self.TCP_PORT = Config.hsm_port
            self.BUFFER_SIZE = 1024
            self.socket_connection = self.__Connect()

        def __Connect(self):
            self.log.debug("Connecting to Thales on address %s:%s" % (self.TCP_IP, self.TCP_PORT))
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # self.sock.setdefaulttimeout(10000)
            self.sock.connect((self.TCP_IP, self.TCP_PORT))
            self.sock.settimeout(None)
            self.log.debug("Connected.")
            return self.sock


    def __init__( self):
        if ThalesConnector._iInstance is None:
            ThalesConnector._iInstance = ThalesConnector.Singleton()
        self._EventHandler_instance = ThalesConnector._iInstance



    def __getattr__(self, aAttr):
        return getattr(self._iInstance, aAttr)

    def __setattr__(self, aAttr, aValue):
        return setattr(self._iInstance, aAttr, aValue)

class Thales9000():


    @staticmethod
    def SendMessage(Command):
        try:
            socket_connection = ThalesConnector().socket_connection
        except Exception as exe:
            raise
        response = ''
        try:
            Header = 'HEAD'
            Command = Header + Command
            Size = pack('>h', len(Command))

            Message = Size + Command

            #print Message

            sent = socket_connection.send(Message)
            response = socket_connection.recv(1024)

        finally:
            return response


