__author__ = 'root'
from Unit_Tests.UnitTest_ATMClient import *


while True:
    atmid = "S9218163"
    t = ATMClient(atmid)
    t.start()
