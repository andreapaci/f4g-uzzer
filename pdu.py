from const      import *
from test_cases import *


from pycrate_asn1dir            import RRCLTE
from pycrate_mobile.NAS         import *
from pycrate_asn1rt.codecs      import _with_json
from pycrate_asn1rt.asnobj_ext  import *
from CryptoMobile               import CM

import json


class Pdu:
    sep_char = "|  "

    def __init__(self, _pdu, _is_sdu, _msg_number):
        # type: (Pdu, bytes, bool, int) -> Pdu

        # The Packet Data Unit (as bytes)
        self.pdu = _pdu
        # The Packet Data Unit (as struct)
        self.pdu_dict = 0
        # Decoded message as String
        self.decoded_msg = ""
        # True if is UE -> eNB (uplink)
        self.is_sdu = _is_sdu
        # Number of the message (starting from 0)
        self.msg_number = _msg_number
        # Counter of the Struct raw (used as index of access)
        self.counter = 0
        # True if PDU has a NAS message inside
        self.has_nas = False
        # NAS messages (as bytes)
        self.nas = []
        # NAS messages (as json)
        self.nas_json = []
        if self.is_sdu:
            self.msg_type = RRCLTE.EUTRA_RRC_Definitions.UL_DCCH_Message
        else:
            self.msg_type = RRCLTE.EUTRA_RRC_Definitions.DL_DCCH_Message

    # fuzz indicates if a field has to be changed, fuzz_index means there's a fuzzing procedure (test all fields)
    def decode(self, print_info=True, decodeNAS=False, fuzz=False, row=0, new_val=0, fuzz_index=None, new_pdu=True):
        self.msg_type.from_uper(self.pdu)
        if new_pdu:
            self.pdu_dict = self.msg_type()

        self.decoded_msg = ""
        self.counter = 0
        self.nas = []
        self.nas_json = []
        # TODO: reimposta il Correct_test e Correct_ws_test a True e metti delf.debug_extra sotto print(self.decoded_mesg) e vedi se fallisce con il Radio link failure
        self.debug_extra()

        self.parse_dict(0, 0, self.nas, initial_dict=self.pdu_dict, print_info=print_info, fuzz=fuzz, row=row, content=new_val, fuzz_index=fuzz_index)
        if print_info:
            self.decoded_msg += '\n'
            print(self.decoded_msg)


        if fuzz_index is not None:
            if not fuzz_index.has_next_input and self.counter <= fuzz_index.field + 1:
                fuzz_index.has_next_field = False

        if len(self.nas) != 0:
            self.has_nas = True
            print("NAS Messages: ", self.nas)
        else:
            print("No NAS messages")
        if self.has_nas and decodeNAS:
            for e in self.nas:
                self.decode_nas(e, self.is_sdu, print_info=False)

    def encode(self, asHexString=False):
        try:
            if asHexString:
                return self.msg_type.to_uper(self.pdu_dict).hex()
            else:
                return self.msg_type.to_uper(self.pdu_dict)
        except Exception:
            # NOTE: Raising an exception if the encoding fails is wrong! It would bring a lot of
            # "False" exception which should not be reported
            print(FZ_PREFIX, "Could not encode PDU, returning original PDU")
            if asHexString:
                return self.pdu.hex()
            else:
                return self.pdu

    # Utilities
    def parse_dict(self, container, container_key, nas_info_list, index=0, initial_dict=None, print_info=True, fuzz=False, row=0, content=0, fuzz_index=None):
        # type: (Pdu, object, object, list, int, dict, bool, bool, int, object, object) -> object
        if initial_dict is None:
            initial_dict = container[container_key]
        for key in initial_dict:
            if print_info:
                # print(index * self.sep_char + "KEY " + key, end=' ')
                self.decoded_msg += str(index * self.sep_char) + "KEY " + str(key) + ' '
            self.recursor(initial_dict, key,  nas_info_list, index, print_info=print_info, fuzz=fuzz, row=row, content=content, fuzz_index=fuzz_index)
            if key == "dedicatedInfoNAS":
                nas_info_list.append(initial_dict[key])
            elif key == "dedicatedInfoType":
                nas_info_list.append(initial_dict[key][1])
            elif key == "dedicatedInfoNASList":
                for e in initial_dict[key]:
                    nas_info_list.append(e)

        return

    def parse_tuple(self, container, container_key, nas_info_list, index=0, print_info=True, fuzz=False, row=0, content=0, fuzz_index=None):
        # type: (Pdu, object, object, list, int, bool,  bool, int, object, object) -> object

        # Necessary conversion to enable modification to the tuple
        container[container_key] = list(container[container_key])

        for j in range(0, len(container[container_key])):
            if print_info:
                # print(index * self.sep_char, end='')
                self.decoded_msg += str(index * self.sep_char)
            self.recursor(container[container_key], j, nas_info_list, index, print_info=print_info, fuzz=fuzz, row=row, content=content, fuzz_index=fuzz_index)

        container[container_key] = tuple(container[container_key])
        return


    def recursor(self, container, container_key, nas_info_list, index, print_info=True, fuzz=False, row=0, content=None, fuzz_index=None):
        if print_info:
            elem_type = str.upper(type(container[container_key]).__name__)
            # print(elem_type, end=' ')
            self.decoded_msg += elem_type + ' '
        if isinstance(container[container_key], dict):
            if print_info:
                # print("")
                self.decoded_msg += '\n'
            self.parse_dict(container, container_key, nas_info_list, index + 1, print_info=print_info, fuzz=fuzz, row=row, content=content, fuzz_index=fuzz_index)
        elif isinstance(container[container_key], tuple) or isinstance(container[container_key], list):
            if print_info:
                # print("")
                self.decoded_msg += '\n'
            self.parse_tuple(container, container_key, nas_info_list, index + 1, print_info=print_info, fuzz=fuzz, row=row, content=content, fuzz_index=fuzz_index)
        else:
            if print_info:
                if elem_type == "BYTES":
                    # print(container[container_key].hex(), "(", self.counter, ")")
                    self.decoded_msg += container[container_key].hex() + "(" + str(self.counter) + ")\n"
                else:
                    # print(container[container_key], "(", self.counter, ")")
                    self.decoded_msg += str(container[container_key]) + "(" + str(self.counter) + ")\n"

            # Change single value (no fuzzing)
            if fuzz and row == self.counter:
                print("CHANGED")
                container[container_key] = content

            # Fuzz multiple values
            if fuzz_index is not None:
                if self.msg_number == fuzz_index.message and self.counter == fuzz_index.field:
                    print("FUZZED")
                    # If the element type is not in the defined ones (BYTE, STRING, Ecc..) raise exception and switch to the next field
                    if elem_type not in TEST_VALUES:
                        print(FZ_PREFIX, "Unspecified type:", elem_type, "at position", self.counter)
                        fuzz_index.has_next_input = False
                        raise Exception("Unspecified type: " + elem_type)

                    # Assign the test values according to the element type
                    test_values = TEST_VALUES[elem_type]

                    container[container_key] = test_values[fuzz_index.test_input_index]
                    # If last value to be tested
                    if fuzz_index.test_input_index >= len(test_values) - 1:
                        fuzz_index.has_next_input = False

            self.counter += 1

        return

    def decode_nas(self, data, is_uplink, recursive=True, print_info=True):
        pdu = data
        m = 0
        e = 0
        try:
            if is_uplink:
                m, e = parse_NAS_MO(pdu)
            else:
                m, e = parse_NAS_MT(pdu)

            v = m.get_val()
            t = m.to_json() + "\n"
            self.nas_json.append(t)

            if print_info:
                print("[DEBUG] Json NAS:", str.upper(type(t).__name__), t.replace("\n", "\n\t") + "\n")
            if recursive:
                self.parse_nas(t, is_uplink, print_info=print_info)
            if CORRECT_NAS_TEST:
                assert (e == 0)
                m.reautomate()
                assert (m.get_val() == v)
                m.set_val(v)
                assert (m.to_bytes() == pdu)
                m.from_json(t)
                assert (m.get_val() == v)
        # TODO: Handle Assertion error to raise another exception
        except AssertionError as error:
            print("Assertion Error")
            raise error
        except Exception:
            print(FZ_PREFIX, "Could not Decode Nas (Probably modified by fuzzer)")



    def parse_nas(self, t, is_uplink, print_info=True):
        j = json.loads(t)
        keys = list(j.keys())
        for e in j[keys[0]]:
            inner_keys = list(e.keys())
            if inner_keys == ["NASMessage"]:
                print("\nInner NAS Message:")
                self.decode_nas(unhexlify(e["NASMessage"]), is_uplink, False, print_info=print_info)
        if CORRECT_NAS_TEST:
            assert (keys == ["EMMSecProtNASMessage"] or
                    keys == ["EMMIdentityRequest"] or
                    keys == ["EMMAuthenticationRequest"] or
                    keys == ["EMMAuthenticationResponse"] or
                    keys == ["EMMAttachRequest"] or
                    keys == ["EMMIdentityResponse"] or
                    keys == ["EMMDetachRequestMO"])

    def debug_extra(self):
        if DEBUG_PDU_PRINT:
            print("[DEBUG] JSON Format\n" + self.msg_type.to_jer())
            print("[DEBUG] Dict print\n", self.msg_type())

        if CORRECT_TEST:
            ret = self.msg_type.to_uper()
            # TODO: in some cases, those two bytes sequence are different even if the decode is the same
            # TODO: instead of comparing bytes, compare the resulting struct (should be the same)
            assert (ret == self.pdu)

        if CORRECT_WS_TEST:
            val = self.msg_type()
            self.msg_type.from_uper_ws(self.pdu)
            val_ws = self.msg_type()
            struct = self.msg_type._struct()
            ret = self.msg_type.to_uper_ws()
            assert (ret == self.pdu)
            assert (val == val_ws)
            assert (self.msg_type._struct() == struct)
            txt = self.msg_type.to_asn1()
            self.msg_type.from_asn1(txt)
            assert (self.msg_type() == val)