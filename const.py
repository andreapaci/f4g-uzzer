from binascii import *

# Set to true if it's required to launch the Core Network inside the python fuzzer
#CN_LAUNCH = False
CN_LAUNCH = True

# Set to true if it's required to launch the eNB inside the python fuzzer
#ENB_LAUNCH = False
ENB_LAUNCH = True

# Set to true if it's required to launch the Core Network inside the python fuzzer
#UE_LAUNCH = False
UE_LAUNCH = True

# Set to true if a new context has to be launched
CTXT_DELETE = True


# Text prefix for Core Network, eNB, UE and Fuzzer
CN_PREFIX = "[CoNe]"
NB_PREFIX = "[eNoB]"
UE_PREFIX = "[UsEq]"
FZ_PREFIX = "[Fuzz]"


# String to print in case of Success/Failure
SUCC_TEXT = "Success!"
FAIL_TEXT = "Failure!"

# Path to build folder of EPC/ENB/UE and configuration files
BUILDS_PATH = "/home/andrea/Desktop/mysrsran/srsRAN/build/"
CONFIG_PATH = "/home/andrea/.config/srsran/"


# Paths to UE, ENB and EPC as List (could also have been done with string.split())
CN_PATH = ['sudo', BUILDS_PATH + 'srsepc/src/srsepc']
NB_PATH = ['sudo', BUILDS_PATH + 'srsenb/src/srsenb',  CONFIG_PATH + 'enb.conf', '--rf.device_name=zmq',
           '--rf.device_args="fail_on_disconnect=true,tx_port=tcp://*:2000,rx_port=tcp://localhost:2001,id=enb,base_srate=23.04e6"']
UE_PATH = ['sudo', BUILDS_PATH + 'srsue/src/srsue', CONFIG_PATH + 'ue.conf', '--rf.device_name=zmq',
           '--rf.device_args="tx_port=tcp://*:2001,rx_port=tcp://localhost:2000,id=ue,base_srate=23.04e6"',
           '--gw.netns=ue1']
UE_IMSI_PARAM = '--usim.imsi='

# Delay in seconds between the run of EPC, eNB and UE (in this order)
SHELL_RUN_DELAY = 3
# Delay between each RUN
RUN_DELAY = 5


# Outcome dictonary Keys
OUTCOME_SUCC = 'successful'
OUTCOME_TYPE = 'type'
# The element defined by the key 'type' can be one of this
OUTCOME_TYPE_TIME = 'time'
OUTCOME_TYPE_TEXT = 'text'
OUTCOME_TYPE_EXCE = 'exception'
OUTCOME_TYPE_INTE = 'keyboard_interrupt'


# Values to stop the EPC/ENB/UE running

# When the UE has to stop by default (when it receives this output the run went well)
DEF_UE_SUCC_TEXT = ["Software Radio Systems RAN (srsRAN)"]
DEF_UE_FAIL_TEXT = ["Radio-Link Failure"]  # Forse anche "Attach failed"
# If the UE doesn't respond for 'x' seconds, it means there's a failure
DEF_UE_FAIL_TIME = 10

# ------------------------------------------------------------------------------------

# Print human-readable PDUs debug information (eg. Json format)
DEBUG_PDU_PRINT = False
# Print human-readable NAS Messages
DEBUG_NAS_PRINT = True

# Note: if fuzzing is enabled, leave both test to False or else it will raise an error
# Test if encode/decode operation return the same
CORRECT_TEST = False
# Test if the WS version is the same as non-WS
CORRECT_WS_TEST = False

# Check NAS translation to json if contains expected keys
CORRECT_NAS_TEST = True

# Test data
pdu1 = unhexlify('201610800000068B02801289F7BB16FC8041D0804F8180003C440001C0075480704041C1C19CDC9CD85C1B81406B04000089C220000341020202021402FD803C4400004687D6C919C4C03C44000048C17D07D6C919D89F07D40BE3A43C733CB833321834C00026408000F8')
nas1 = unhexlify('0742013E060000F1100007001D5201C10107070673727361706E0501AC100002270880000D0408080808500BF600F11000011A1F5B24671300F11000012305F41F5B2467')

#message_to_fuzz = 0
#message_send = b'\x12\x13\x14'*15  # Trigger RRC conn Reconfiguration complete
#message_send = b'\xff\xff\xff'*15
#message_entry = 5
#message_content = 2
