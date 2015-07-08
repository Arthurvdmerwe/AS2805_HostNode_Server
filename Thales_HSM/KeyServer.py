__author__ = 'root'
import MySQLdb

from Shared.bottle import route, run
import KeyGenerator
from Shared.Database import SwitchDatabase


con = SwitchDatabase().get_connection()


@route('/TMK/<ATMID>')
def index(ATMID):
    data = KeyGenerator.GenerateKeys_TMK()
    UpdateTMK(ATMID, data['TMK'], data['TMK_Check'])
    # Save Terminal Info
    #data['TMK'] = '1234567890123456'
    return    'TERMINAL:'+ATMID + '</BR> ** MASTER KEY *** </BR></BR>' + data['TMK'][1:5] + '-' + data['TMK'][5:9] + '-' + data['TMK'][9:13] + '-' + data['TMK'][13:17] +  '</BR>' + data['TMK'][17:21] + '-' + data['TMK'][21:25] + '-' + data['TMK'][25:29] + '-' + data['TMK'][29:33] + '</BR> *** KCV *** </BR>' + \
           data['TMK_Check']


@route('/TAK/<ATMID>')
def index(ATMID):
    data = KeyGenerator.GenerateKeys_TAK()
    # Save Terminal Info
    UpdateTAK(ATMID, data['TAK'], data['TAK_Check'])
    return 'TERMINAL:'+ ATMID + '</BR> ** MAC KEY *** </BR></BR>' + data['TAK'][1:5] + '-' + data['TAK'][5:9] + '-' + data['TAK'][9:13] + '-' + data['TAK'][13:17] +  '</BR>' + data['TAK'][17:21] + '-' + data['TAK'][21:25] + '-' + data['TAK'][25:29] + '-' + data['TAK'][29:33] + '</BR></BR> *** KCV *** </BR>' + \
           data['TAK_Check']


@route('/CreateTerminal/<ATMID>;<NAME>;<CITY>;<STATE>')
def index(ATMID, NAME, CITY, STATE):
    CreateTerminal(ATMID, NAME, CITY, STATE)


def UpdateTMK(Atmid, TMK, KCV):
    cur = con.cursor(MySQLdb.cursors.DictCursor)
    sql = """UPDATE sessions_triton
             SET TMK = "%s",
             TMK_CHK = "%s"
             WHERE atm_id = "%s"

             """ % \
          (TMK, KCV, Atmid)
    cur.execute(sql)


def CreateTerminal(ATMID, NAME, CITY, STATE):
    cur = con.cursor(MySQLdb.cursors.DictCursor)
    sql = """INSERT INTO sessions_triton (atm_id, name_location_name, name_location_city,name_location_state)
              VALUES ('%s', '%s', '%s', '%s')
             """ % \
          (ATMID, NAME, CITY, STATE)
    cur.execute(sql)


def UpdateTAK(Atmid, TAK, KCV):
    cur = con.cursor(MySQLdb.cursors.DictCursor)
    sql = """UPDATE sessions_triton
             SET TAK = "%s",
             TAK_CHK = "%s"
             WHERE atm_id = "%s"

             """ % \
          (TAK, KCV, Atmid)
    cur.execute(sql)


run(host='localhost', port=8080)