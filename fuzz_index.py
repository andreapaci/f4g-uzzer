# This class represent the Index used for fuzzing (i.e. scroll through all the possibile combinations)
class Fuzz_Index:

    def __init__(self, _message=0, _field=0, _input_index=0):
        # Message to be fuzzed
        self.message = 0
        # Field of the message to be fuzzed
        self.field = 0
        # Index representing which value has to be overwritten in the field
        self.test_input_index = 0
        # If the message has another field to be fuzzed
        self.has_next_field = True
        # If it has a next input to be used as test case
        self.has_next_input = True

    def next(self):
        if self.has_next_input:
            self.test_input_index += 1
        elif self.has_next_field:
            self.field += 1
            self.test_input_index = 0
            self.has_next_input = True
        else:
            self.message += 1
            self.field = 0
            self.test_input_index = 0
            self.has_next_field = True
            self.has_next_input = True

