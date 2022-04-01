# This define a stop condition for a program, both succesfull and failing
# The condition to be evaluated are (both for good and bad outcome)
#   - Timeout between prints (if the program doesn't send an output for x seconds)
#   - Output contains specific text
#   - Response message is not valid
class Stop_Cond:

    def __init__(self):
        self.success_text = []
        self.success_timeout = None

        self.fail_text = []
        self.fail_timeout = None
