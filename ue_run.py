# Class defining a UE run to be fuzzed

from pdu            import *
from const          import *
from shell_runner   import *
from stop_cond      import *

import zmq

import time
import threading
import sys
import traceback


class Ue_Run:

    # IF:
    #   - msg_fuzz = None means that no specific message/field has to be changed with different content
    #   - fuzz_index = None means that it's not running for fuzzing all possible fields
    #   - BOTH are None means that the run it's just decoding
    # TODO: se entrambi presenti? riscrevere meglio il codice (ha la precedenza msg_fuzz con il codice così scritto)
    def __init__(self, _imsi, _outcome, msg_fuzz=None, fuzz_index=None):
        # Pad IMSI to achieve 15 number long string
        self.imsi = str(_imsi).zfill(15)
        self.msg_fuzz = msg_fuzz
        self.fuzz_index = fuzz_index

        # Indexes counting UL & DL Messages
        self.ul_messages = 0
        self.dl_messages = 0

        # Create ZeroMQ Request-Reply server
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REP)
        self.socket.bind("tcp://127.0.0.1:5555")

        # Register Poller (Used to Poll ZMQ Queue without consuming the message/stalling waiting for a message)
        self.poller = zmq.Poller()
        self.poller.register(self.socket, zmq.POLLIN)


        # Setting the conditions. HARD CODED VALUE, CAN BE CHANGED FOR EACH RUN
        self.ue_cond = Stop_Cond()
        self.ue_cond.success_text = DEF_UE_SUCC_TEXT
        self.ue_cond.fail_text = DEF_UE_FAIL_TEXT
        self.ue_cond.fail_timeout = DEF_UE_FAIL_TIME

        # Boolean variable used to stop the main (fuzzer) thread
        self.is_running = [True]

        self.outcome = _outcome

    def run(self):

        thread_run = threading.Thread(target=self.run_thread)
        thread_run.daemon = True
        thread_run.start()

        cn_runner = None
        enb_runner = None
        ue_runner = None

        if CN_LAUNCH:
            print(FZ_PREFIX, "Launcing Core Network...")
            cn_runner = Shell_Runner(CN_PATH, CN_PREFIX, self.is_running, self.outcome)
            cn_runner.run()
            print(FZ_PREFIX, "CN Launched, waiting", SHELL_RUN_DELAY, "seconds before proceeding...")
            time.sleep(SHELL_RUN_DELAY)

        if ENB_LAUNCH:
            print(FZ_PREFIX, "Launching eNB")
            enb_runner = Shell_Runner(NB_PATH, NB_PREFIX, self.is_running, self.outcome)
            enb_runner.run()
            print(FZ_PREFIX, "eNB Launched, waiting", SHELL_RUN_DELAY, "seconds before proceeding...")
            time.sleep(SHELL_RUN_DELAY)

        if UE_LAUNCH:
            print(FZ_PREFIX, "Launching UE")
            if CTXT_DELETE:
                self.remove_ctxt()
            ue_runner = Shell_Runner(UE_PATH, UE_PREFIX, self.is_running, self.outcome, _extra_params=UE_IMSI_PARAM + self.imsi, _stop_cond=self.ue_cond)
            ue_runner.run()
            print(FZ_PREFIX, "UE Launched.")

        # Wait for the end of execution
        thread_run.join()

        print(FZ_PREFIX, "Killing remaining threads...")

        if ue_runner is not None:
            ue_runner.kill_threads()
        if enb_runner is not None:
            enb_runner.kill_threads()
        if cn_runner is not None:
            cn_runner.kill_threads()

        print(FZ_PREFIX, "Run with IMSI =", self.imsi, "killed.")



    def run_thread(self):

        message = None
        try:
            while self.is_running[0]:

                # Capture the packet (POLL because it doesn't Wait of the message has not yet arrived)
                poll_data = dict(self.poller.poll(5))
                if poll_data:
                    if poll_data.get(self.socket) == zmq.POLLIN:
                        message = self.socket.recv()
                else:
                    continue

                # First byte sent by the UE is used to determine if it's an uplink or downlink packet
                # If UE -> eNB
                if message[0] == 1:
                    pdu = Pdu(message[1:], True, self.ul_messages)
                    print(FZ_PREFIX, "[ UL Message", self.ul_messages, "received SDU", message[1:].hex(), "]\n")

                    # If message has to be changed (no fuzzing, just a specific message)
                    if self.ul_messages in self.msg_fuzz:

                        # If the message to fuzz is byte only (no field parsing)
                        if self.msg_fuzz[self.ul_messages].is_byte:
                            pdu.decode(decodeNAS=True)

                            print(FZ_PREFIX, "Sending bytes", self.msg_fuzz[self.ul_messages].msg_val.hex())
                            self.socket.send(self.msg_fuzz[self.ul_messages].msg_val)

                        # If a specific field has to be fuzzed
                        else:
                            pdu.decode(decodeNAS=True, fuzz=True, row=self.msg_fuzz[self.ul_messages].msg_entry,
                                       new_val=self.msg_fuzz[self.ul_messages].new_val)

                            pdu_send = pdu.encode()
                            print(FZ_PREFIX, "Sending encoded", pdu_send.hex())
                            self.socket.send(pdu_send)

                    # If the fuzzing is enabled...
                    elif self.fuzz_index is not None:
                        # ... and this is the message to be fuzzed
                        if self.ul_messages == self.fuzz_index.message:
                            pdu.decode(decodeNAS=True, fuzz_index=self.fuzz_index)

                            pdu_send = pdu.encode()
                            print(FZ_PREFIX, "Sending fuzzed", pdu_send.hex())
                            self.socket.send(pdu_send)

                    # If message has only to be decoded
                    else:
                        pdu.decode(decodeNAS=True)

                        print(FZ_PREFIX, "Sending original", pdu.pdu.hex())
                        self.socket.send(pdu.pdu)

                    # Increment the number of UL message
                    self.ul_messages += 1

                # If eNB -> UE
                else:
                    pdu = Pdu(message[1:], False, self.dl_messages)
                    print(FZ_PREFIX, "[ DL Message", self.dl_messages, "received PDU", message[1:].hex(), "]\n")

                    pdu.decode(decodeNAS=True)
                    # Useless to send a message
                    self.socket.send(b'\x12')

                    # Increment the number of DL Messages
                    self.dl_messages += 1

                print("\n")
                print("+-" * 45, "\n\n")

        except KeyboardInterrupt:
            print("Keyboard interrupt")
            if len(self.outcome) == 0:
                self.outcome[const.OUTCOME_SUCC] = False
                self.outcome[const.OUTCOME_TYPE] = const.OUTCOME_TYPE_INTE
        except Exception as error:
            # TODO: Set a "saving point" that reports this failure (this failure as another failure in Shell_runner (ex. stderr) or even others)
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)  # Fixed format
            tb_info = traceback.extract_tb(tb)
            filename, line, func, text = tb_info[-1]

            print('An error occurred on line {} in statement {}'.format(line, text))
            print(type(error).__name__, error)

            if len(self.outcome) == 0:
                self.outcome[const.OUTCOME_SUCC] = False
                self.outcome[const.OUTCOME_TYPE] = const.OUTCOME_TYPE_EXCE + ": " + str(error) + "(" + (str(filename) + ":" + str(line)) + ")"
        finally:
            print(FZ_PREFIX, "Main thread Exited...")
            self.socket.close()
            self.context.term()
            
    # ---------------------------------------------- Utilities ---------------------------------------------- #

    # Remove security context file
    def remove_ctxt(self):
        print(FZ_PREFIX, "Deleting Security context")
        del_ctxt = subprocess.call(["sudo", "rm", ".ctxt"],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     universal_newlines=True)
        print(FZ_PREFIX, "Output of deletition:", del_ctxt)
        
        


        
