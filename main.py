
from const          import *
from ue_run         import Ue_Run
from msg_fuzz       import Msg_Fuzz
from shell_runner   import Shell_Runner
import time
import subprocess
import threading
from pycrate_asn1rt.codecs      import _with_json
from pycrate_asn1rt.asnobj_ext  import *
from CryptoMobile               import CM

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




def fuzzer():

    run_index = 0
    imsi = 15000
    # imsi = 23456789123456

    msg_fuzz = {}
    # msg_fuzz = {0: Msg_Fuzz(0, msg_val=b'\x10')} (Trigger RADIO LINK FAILURE)
    # msg_fuzz = {0: Msg_Fuzz(0, msg_entry=5, new_val=5)}


    print(FZ_PREFIX, "-" * 40, "Run", run_index, "with IMSI", imsi, "-" * 40)
    print(FZ_PREFIX, "Launching eNB/UE with imsi =", imsi, 'and message to fuzz =', msg_fuzz)
    # It's possible to:
    #  - Fuzz a specific message changing bytes
    #  - Fuzz a specific field of a specific message (even multiple ones)
    #  - Iterate through all possible values of all possible fields

    print("ACTIVE threads:", threading.active_count())
    ue_run = Ue_Run(imsi, msg_fuzz=msg_fuzz)
    ue_run.run()

    print("Sleeping")
    print("ACTIVE threads:", threading.active_count())
    time.sleep(RUN_DELAY)
    print("ACTIVE threads:", threading.active_count())

    print(FZ_PREFIX, "-" * 100)
    print("\n\n\n\n\n")

    imsi = 23456789123456
    run_index += 1

    print(FZ_PREFIX, "-" * 40, "Run", run_index, "with IMSI", imsi, "-" * 40)
    print(FZ_PREFIX, "Launching eNB/UE with imsi =", imsi, 'and message to fuzz =', msg_fuzz)
    # It's possible to:
    #  - Fuzz a specific message changing bytes
    #  - Fuzz a specific field of a specific message (even multiple ones)
    #  - Iterate through all possible values of all possible fields

    ue_run2 = Ue_Run(imsi, msg_fuzz=msg_fuzz)
    ue_run2.run()

    time.sleep(SHELL_RUN_DELAY)
    print(FZ_PREFIX, "-" * 100)
    print("\n\n\n\n\n")

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
    fuzzer()
