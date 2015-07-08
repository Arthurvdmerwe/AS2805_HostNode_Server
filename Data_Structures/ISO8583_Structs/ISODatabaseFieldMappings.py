'''
This file maps the database field names with the ISO8583 bit numbers
'''

import MySQLdb

from ISO8583 import ISO8583


ISO8583_to_DB = {"2": "p2_pan", "3": "p3_processing_code", "4": "p4_amount_tran", "5": "p5_amount_recon",
                 "6": "p6_amount_card_billing", "7": "p7_transmit_dt", "8": "p8_amount_cardholder_billing_fee",
                 "9": "p9_conversion_rate_recon", "10": "p10_conv_rate_card_billing", "11": "p11_stan",
                 "12": "p12_time_local_tran", "13": "p13_date_local_tran", "14": "p14_date_expiration",
                 "15": "p15_date_settlement", "16": "p16_date_conversion", "17": "p17_date_capture",
                 "18": "p18_merchant_type", "19": "p19_country_acquiring_institution", "20": "p20_country_code_pan",
                 "21": "p21_transaction_life_cycle_identification_data", "22": "p22_pos_entry_mode",
                 "23": "p23_card_seq_no", "24": "p24_function_code", "25": "p25_pos_condition_code",
                 "26": "p26_merchant_category_code", "27": "p27_point_of_service_capability", "28": "p28_amt_tran_fee",
                 "29": "p29_recon_indicator", "30": "p30_amt_process_fee", "31": "p31_acq_reference_number",
                 "32": "p32_acq_inst_id", "33": "p33_fwd_inst_id", "34": "p34_elec_commerce_data", "35": "p35_track2",
                 "36": "p36_track3", "37": "p37_ret_ref_no", "38": "p38_auth_id_response", "39": "p39_response_code",
                 "40": "p40_service_restr_code", "41": "p41_terminal_id", "42": "p42_card_acceptor_id",
                 "43": "p43_name_location", "44": "p44_additional_response data", "45": "p45_track1",
                 "46": "p46_amounts_fees", "47": "p47_additional_national", "48": "p48_additional_private",
                 "49": "p49_verification_data", "50": "p50_currency_settle",
                 "51": "p51_currency_code_cardholder_billing", "52": "p52_pin_block",
                 "53": "p53_security_related_control_information", "54": "p54_additional_amounts",
                 "55": "p55_icc_system_related_data", "56": "p56_original_data_elements",
                 "57": "p57_auth_life_cycle_code", "58": "p58_auth_agent_inst_id_code", "59": "p59_echo_data",
                 "60": "p60_national_use", "61": "p61_national_use", "62": "p62_national_use", "63": "p63_national_use",
                 "64": "p64_mac", "65": "p65_bitmap_tertiary", "66": "p66_settlement_code",
                 "67": "p67_extended_payment_data", "68": "p68_receiving_inst_country_code",
                 "69": "p69_settlement_inst_county_code", "70": "p70_network_mgt_info_code", "71": "p71_message_no",
                 "72": "p72_data_record", "73": "p73_date_action", "74": "p74_credits_no", "75": "p75_credits_rev_no",
                 "76": "p76_debits_no", "77": "p77_debits_rev_no", "78": "p78_transfers_no",
                 "79": "p79_transfers_rev_no", "80": "p80_inquiries_no", "81": "p81_auths_no",
                 "82": "p82_credits_proc_fee", "83": "p83_credits_tran_fee", "84": "p84_debits_proc_fee",
                 "85": "p85_debits_tran_fee", "86": "p86_credits_amt", "87": "p87_credits_rev_amt",
                 "88": "p88_debits_amt", "89": "p89_debits_rev_amt", "90": "p90_original_data",
                 "91": "p91_file_update_code", "92": "p92_file_security_code", "93": "p93_response_indicator",
                 "94": "p94_service_indicator", "95": "p95_replacement_amounts", "96": "p96_message_security_code",
                 "97": "p97_amt_net_settle", "98": "p97_payee", "99": "p99_settle_inst_id_code",
                 "100": "p100_receiving_inst_id_code", "101": "p101_file_name", "102": "p102_account_ident_1",
                 "103": "p103_account_ident_2", "104": "p104_transaction_desc", "105": "p105_reserved_for_iso_use",
                 "106": "p106_reserved_for_iso_use", "107": "p107_reserved_for_iso_use",
                 "108": "p108_reserved_for_iso_use", "109": "p109_reserved_for_iso_use",
                 "110": "p110_reserved_for_iso_use", "111": "p111_reserved_for_private_use",
                 "112": "p112_reserved_for_private_use", "113": "p113_reserved_for_private_use",
                 "114": "p114_reserved_for_national_use", "115": "p115_reserved_for_national_use",
                 "116": "p116_reserved_for_national_use", "117": "p117_reserved_for_national_use",
                 "118": "p118_reserved_for_national_use", "119": "p119_reserved_for_national_use",
                 "120": "p120_reserved_for_private_use", "121": "p121_reserved_for_private_use",
                 "122": "p122_reserved_for_private_use", "123": "p123_reserved_for_private_use",
                 "124": "p124_info_text", "125": "p125_network_management_info", "126": "p126_issuer_trace_id",
                 "127": "p127_reserved_for_private_use", "128": "p128_mac"}


def BuildISOInsertFieldAndValues(iso, extra={}):
    """
    Builds an insert statement to save all the fields from an ISO8583 message into the database.postbridge table
    extra = a dictionary with extra field/value pairs that you want to insert that is not part of the ISO message
    """
    if not extra: extra = {}
    v1 = iso.getBitsAndValues()
    field_list = ''
    value_list = ''
    fields_in_row = 0
    for v in v1:
#        log.debug('Bit %s of type %s with value = %s' % (v['bit'], v['type'], v['value']))
        # Add a comma between the fields
        try:
            field_name = ISO8583_to_DB[v['bit']]
            if field_list != '':
                fields_in_row += 1
                field_list += ', '
                value_list += ', '
            # Add a new line every 5 fields.
            if fields_in_row >= 5:
                field_list += '\n  '
                value_list += '\n  '
                fields_in_row = 0
            field_list += field_name
            value_list += '"' + MySQLdb.escape_string(v['value']) + '"'
        except KeyError as e:
            print e

    for extra_field in extra.keys():
        field_list += ',\n  %s' % extra_field
        v = str(extra[extra_field])
        value_list += ',\n   "%s"' % MySQLdb.escape_string(v)
        
    #Chop off the extra comma's if there are extra fields
#    if extra != {}:
#        field_list = field_list[:-2] 
#        value_list = value_list[:-2] 

    sql  = 'INSERT INTO core_node (\n'
    sql += '  MTI,\n'
    sql += '  ' + field_list + ')\n'
    sql += 'VALUES (\n'
    sql += '  "%s",\n' % (iso.getMTI())
    sql += '  ' + value_list + ')'
    return sql


def BuildISOUpdateFieldAndValues(uuid, iso, extra=None):

    if not extra: extra = {}
    v1 = iso.getBitsAndValues()
    field_list = ''

    fields_in_row = 0
    for v in v1:

        try:
            field_name = ISO8583_to_DB[v['bit']]
            if field_list != '':
                fields_in_row += 1
                field_list += ' , '
            # Add a new line every 5 fields.
            if fields_in_row >= 5:
                field_list += '\n  '
                fields_in_row = 0
            field_list += field_name + '="' + MySQLdb.escape_string(v['value']) + '"'
        except KeyError as e:
            print 'Bit does not exist in the database: ' + str(e)

    for extra_field in extra.keys():
        #field_list += ',\n  %s' % extra_field
        v = str(extra[extra_field])
        field_list +=  ", " + extra_field + '="' + MySQLdb.escape_string(v) + '"'

    sql = "UPDATE core_node SET "
    sql +=  field_list
    sql += " WHERE tran_gid " + '="' + uuid + '"'

    return sql

def Get_ISO_from_Database_Table(cur, tran_gid, mti):

    try:

        cur.execute('SELECT * FROM core_node where tran_gid = "%s"   and MTI = "%s" limit 1' % (tran_gid, mti))
        r = cur.fetchone()
        if r > 0:
            result_list = r
            resp_iso = ISO8583()
            resp_iso.setMTI(result_list['MTI'])
            for item in result_list:
                bit_number = item.split('_')[0][1:]
                if bit_number is not None and result_list[item] is not None and __isInt(bit_number):
                    data_type = resp_iso.getBitType(int(bit_number))
                  #  print "Data Type: " + data_type
                  #  print "Bit: " + bit_number
                  #  print "Value: " + result_list[item]
                    if data_type == 'L':
                        result_list[item] = result_list[item][1:]
                    elif data_type == 'LL':
                        result_list[item] = result_list[item][2:]
                    elif data_type == 'LLL':
                        result_list[item] = result_list[item][3:]
                    elif data_type == 'LLLL':
                        result_list[item] = result_list[item][4:]

                    resp_iso.setBit(int(bit_number), MySQLdb.escape_string(result_list[item]))
            return resp_iso
        else:
            return None
    except Exception as e:
        print e.message
    finally:
        cur.close()



def __isInt(s):
    try:
        if type(int(s)) is int:
            return True
        else:
            return False
    except:
        return False
