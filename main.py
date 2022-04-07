from const          import *
from ue_run         import Ue_Run
from fuzz_index     import *
from msg_fuzz       import *

from pycrate_asn1rt.asnobj_ext  import *

import datetime
import subprocess

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




def run():
    f = open("report", "a")
    f.write("\n" + "-" * 15 + " Run started at " + str(datetime.datetime.now().date()) + " " + str(datetime.datetime.now().time())[:8] + " " + "-" * 15 + "\n")

    #send_specific_message(f)

    fuzz(f)

    f.close()


def send_specific_message(f):

    imsi = 15000
    # imsi = 23456789123456

    msg_fuzz = {}
    # Dict Format {UL_Message_Number: Msg_Fuzz(UL_Message_Number, other fields)
    # msg_fuzz = {0: Msg_Fuzz(0, msg_val=b'\x10')} # (Trigger RADIO LINK FAILURE)
    # msg_fuzz = {0: Msg_Fuzz(0, msg_entry=5, new_val=5)}
    # msg_fuzz = {1: Msg_Fuzz(1, msg_entry=5, new_val=b'\x12\x34')}  # Test Tuple ( CRASH CORE NETWORK )

    outcome = {}

    print(FZ_PREFIX, "-" * 40, "Run with IMSI", imsi, "-" * 40)
    print(FZ_PREFIX, "Launching eNB/UE with imsi =", imsi, 'and message to fuzz =', msg_fuzz)
    # It's possible to:
    #  - Fuzz a specific message changing bytes
    #  - Fuzz a specific field of a specific message (even multiple ones)
    #  - Iterate through all possible values of all possible fields

    ue_run = Ue_Run(imsi, outcome, msg_fuzz=msg_fuzz)
    ue_run.run()

    print(outcome)

    print(FZ_PREFIX, "-" * 100)
    print("\n\n\n\n\n")

    if not outcome[OUTCOME_SUCC]:
        # TODO: print msg_fuzz info in outcome
        f.write(str(outcome) + "\n")


# It's possible to:
#  - Fuzz a specific message changing bytes
#  - Fuzz a specific field of a specific message (even multiple ones)
#  - Iterate through all possible values of all possible fields
def fuzz(f):
    # Starting IMSI
    imsi = 15
    index = Fuzz_Index()

    # Messages to be tested
    while index.message < 2:
        print(FZ_PREFIX, "-" * 40, "Run with IMSI", imsi, "-" * 40)
        print(FZ_PREFIX, "Launching eNB/UE with imsi =", imsi, 'and message to fuzz =')

        outcome = {}

        ue_run = Ue_Run(imsi, outcome, fuzz_index=index)
        ue_run.run()

        print(outcome)

        print(FZ_PREFIX, "-" * 100)
        print("\n\n\n\n\n")

        if OUTCOME_SUCC in outcome:
            if not outcome[OUTCOME_SUCC]:
                f.write("message: " + str(index.message) + ", field: " + str(index.field) +
                        ", test_index: " + str(index.test_input_index) + " " + str(outcome) + "\n")
                f.flush()
        else:
            f.write("This run sent non registered Exception")

        # Prepare next iteration
        imsi += 1
        index.next()


# --------------------------------------------- Utilities functions --------------------------------------------- #


def create_net_ns():
    print(FZ_PREFIX, "Deleting Network namespace \"ue1\"")
    del_net_ns = subprocess.call(["sudo", "-E", "ip", "netns", "delete", "ue1"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 universal_newlines=True)
    print(FZ_PREFIX, "Output of deletition:", del_net_ns)

    print(FZ_PREFIX, "Creating Network namespace \"ue1\"")
    add_net_ns = subprocess.call(["sudo", "-E", "ip", "netns", "add", "ue1"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 universal_newlines=True)
    print(FZ_PREFIX, "Output of addition:", add_net_ns)


def delete_existing_srs():
    print(FZ_PREFIX, "Killing existing instances of srsRAN (if they exists)...")
    kill_srs = subprocess.call("sudo ps aux | grep srs | awk '{print $2}' | xargs sudo kill -SIGTERM".split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               universal_newlines=True)
    print(FZ_PREFIX, "Output of Kill:", kill_srs)


if __name__ == '__main__':

    if CN_LAUNCH:
        print(FZ_PREFIX, "Create Network NS...")
        create_net_ns()
        delete_existing_srs()
    run()


