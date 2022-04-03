import subprocess
import threading
import datetime
import time
from queue import Queue, Empty
import ctypes
import os
import signal
import unicodedata


# Defines a Runner for a Shell Program (In this case the Core/eNB/UE)
import const


class Shell_Runner:

    def __init__(self, _process_list, _prefix, _fuzz_running, _extra_params=None, _stop_cond=None):

        # Prefix to be used for printing info
        self.prefix = _prefix

        # The shell command to be run as a list
        self.shell_cmd_list = _process_list.copy()
        # Shell subprocess object
        self.shell_process = None
        # Extra params to be added to the shell program
        if _extra_params is not None:
            self.shell_cmd_list.append(_extra_params)

        print(self.shell_cmd_list)
        # Reference to the fuzzer thread (has to be stopped)
        self.fuzz_running = _fuzz_running
        # If the Shell runner is terminated
        self.is_terminated = False

        # Stop condition for the Shell program
        self.stop_cond = _stop_cond
        # Initialization of condition evaluation bools
        self.is_cond_eval = False
        self.is_cond_time = False
        self.is_cond_text = False

        if self.stop_cond is not None:
            self.is_cond_eval = True

            if self.stop_cond.fail_timeout is not None or self.stop_cond.success_timeout is not None:
                self.is_cond_time = True

            if len(self.stop_cond.fail_text) > 0 or len(self.stop_cond.success_text) > 0:
                self.is_cond_text = True


        # This thread checks the running status of the shell program and choose if the
        # execution is failing or not (eg. specific output or specific timeout between answers)
        self.thread_check = threading.Thread(target=self.check_process)
        self.thread_check.daemon = True




    def run(self):
        self.shell_process = subprocess.Popen(self.shell_cmd_list,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.STDOUT,
                                              preexec_fn=os.setsid)
        # This command avoid that the "readline()" goes in blocking mode
        os.set_blocking(self.shell_process.stdout.fileno(), False)
        self.thread_check.start()

    #def read_process_line(self):
    #    try:
    #        for line in iter(self.shell_process.stdout.readline, b''):
    #            text = line.decode('utf-8', 'ignore')
    #            #print(self.prefix, "A--------")
    #            self.queue.put(text)
    #            #print(line)
    #            #print(self.prefix, "B--------")
    #        self.shell_process.stdout.close()
    #    except Exception as e:
    #        print(self.prefix, "Enqueuer Run stopped by the fuzzer. Cause:", e)

        # old_output = self.process.stdout.readline()
        # while True:
        #    output = self.process.stdout.readline()
        #    if(output != old_output):
        #        print(self.prefix, "[", str(datetime.datetime.now().time())[:11], "]: ", output, sep='', end='')
        #        old_output = output

    def check_process(self):
        start_time = None
        kill_thread = threading.Thread(target=self.kill_threads)
        kill_thread.daemon = True

        if self.is_cond_time:
            start_time = time.time()


        while not self.is_terminated:
            #if not self.is_cond_time and self.prefix == const.UE_PREFIX:
                #print("A")
            output = self.shell_process.stdout.readline().decode('utf-8', 'ignore')
            # If there's some output
            if output != '':
                # Print it
                print(self.prefix, "[", str(datetime.datetime.now().time())[:11], "]: ", output, sep='', end='')
                # Update the last seen stdout message
                if self.is_cond_time:
                    start_time = time.time()

                # TODO: Evaluating condition of text

            # If the condition "time" has to be evaluated and the time has expired
            if self.is_cond_time:
                elapsed_time = time.time() - start_time
                #TODO: if elapsed_time >= self.stop_cond.success_timeout:
                if elapsed_time >= self.stop_cond.fail_timeout:
                    print(self.prefix, "FAIL! Elapsed time expired.")
                    self.is_cond_time = False
                    start_time = time.time()
                    kill_thread.start()
                    # TODO: find a way to print last shell code (calling kill_threads as a thread should do the trick)

        print(self.prefix, "Closing STDOUT")
        self.shell_process.stdout.close()

    def kill_threads(self):
        # Setting correct state
        if not self.is_terminated:
            print("ACTIVE threads:", threading.active_count())

            print(self.prefix, "Killing threads...")

            os.killpg(os.getpgid(self.shell_process.pid), signal.SIGINT)
            time.sleep(10)
            self.shell_process.wait()
            print(self.prefix, "Process killed.")


            self.is_terminated = True

            # Killing fuzzer thread
            self.fuzz_running[0] = False

            print(self.prefix, "Fuzzer thread killed")

            # TODO: check se effettivamente vengono stoppati i thread

            print(self.prefix, "All threads killed.")
