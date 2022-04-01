# Define a model for the message to be fuzzed

class Msg_Fuzz:

    def __init__(self, _msg_number, msg_val=None, msg_entry=None, new_val=None):
        # Fuzzing over the whole byte sequence (no specific field value)
        self.msg_number = _msg_number
        if msg_entry is None:
            self.is_byte = True
            self.msg_val = msg_val
        elif new_val is not None:
            self.is_byte = False
            self.msg_entry = msg_entry
            self.new_val = new_val
        else:
            print("Fatal Error in initializing a message to Fuzz:", _msg_number, msg_val, msg_entry, new_val)
