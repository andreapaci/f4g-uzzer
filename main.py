import zmq
from const import *

# Do not print runtime warnings on screen
ASN1Obj._SILENT = False

# Print ascii representation in comments when returning the ASN.1 textual encoding
# Set to False to enable the parsing of the ASN.1 syntax generated
BIT_STR._ASN_WASC = False
OCT_STR._ASN_WASC = False

# Automatically some fields in RRC, if they have a default value, are omitted. with GET_DEFVAL setted to true, those value are reported
# CANONICAL set to True will remove the extra default value and make it
ASN1CodecPER.GET_DEFVAL = True
ASN1CodecPER.CANONICAL = True


message_to_fuzz = 0
message_send = b'\x12\x13\x14'*15  # Trigger RRC conn Reconfiguration complete
message_send = b'\xff\xff\xff'*15
message_entry = 5
message_content = 2

def zmq_reply():
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("tcp://127.0.0.1:5555")
    ul_messages = 0
    dl_messages = 0
    try:
        while True:
            message = socket.recv()

            if message[0] == 1:
                pdu = Pdu(message[1:], True, ul_messages)
                print("[ UL Message", ul_messages, "received SDU", message[1:].hex(), "]\n")
                if ul_messages == message_to_fuzz:
                    if message_send != 0:
                        pdu.decode(decodeNAS=True)
                        print("Sending bytes", message_send)
                        socket.send(message_send)
                    elif message_entry != -1:
                        pdu.decode(decodeNAS=True, fuzz=True, row=message_entry, new_val=message_content)
                        pdu_send = pdu.encode()
                        print("Sending encoded", pdu_send)
                        socket.send(pdu_send)
                else:
                    pdu.decode(decodeNAS=True)
                    print("Sending original", pdu.pdu)
                    socket.send(pdu.pdu)
                ul_messages += 1

            else:
                pdu = Pdu(message[1:], False, dl_messages)
                print("[ DL Message", dl_messages, "received PDU", message[1:].hex(), "]\n")
                dl_messages += 1
                pdu.decode(decodeNAS=True)
                # Useless to send a message
                socket.send(b'\x12')

            print("\n")
            print("+-" * 45, "\n\n")

    except KeyboardInterrupt:
        socket.close()
    except Exception as error:
        print("ERROR: {}".format(error))
        socket.close()
    socket.close()





if __name__ == '__main__':
    #decode_DL_RRC(pdu1)
    zmq_reply()
