__author__ = 'root'
from threading import Thread

from Unit_Tests.UnitTest_AS2805_Client import *
Termin_id = 1
for p in range(6):

    atmid = "9VDD900" + str(Termin_id)
    client = AS2895Client()
    t = Thread(target=client.Process(atmid), args = (atmid,))
    t.start()
    Termin_id += 1