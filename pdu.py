from pycrate_asn1dir            import RRCLTE
from pycrate_mobile.NAS         import *

import const
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

    def decode(self, decodeNAS=False, fuzz=False, row=0, new_val=0):
        self.msg_type.from_uper(self.pdu)
        self.pdu_dict = self.msg_type()
        self.nas = []
        self.parse_dict(0, 0, self.nas, initial_dict=self.pdu_dict, print_info=True, fuzz=fuzz, row=row, content=new_val)

        self.debug_extra()

        if len(self.nas) != 0:
            self.has_nas = True
            print("NAS Messages: ", self.nas)
        else:
            print("No NAS messages")
        if self.has_nas and decodeNAS:
            for e in self.nas:
                self.decode_nas(e, self.is_sdu)

    def encode(self, asHexString=False):
        if asHexString:
            return self.msg_type.to_uper(self.pdu_dict).hex()
        else:
            return self.msg_type.to_uper(self.pdu_dict)

    # Utilities
    def parse_dict(self, container, container_key, nas_info_list, index=0, initial_dict={}, print_info=True, fuzz=False, row=0, content=0):
        # type: (Pdu, object, object, list, int, dict, bool, bool, int, object) -> object
        if initial_dict == {}:
            initial_dict = container[container_key]
        for key in initial_dict:
            if print_info:
                print(index * self.sep_char + "KEY " + key, end=' ')
            self.recursor(initial_dict, key,  nas_info_list, index, print_info=print_info, fuzz=fuzz, row=row, content=content)
            if key == "dedicatedInfoNAS":
                nas_info_list.append(initial_dict[key])
            elif key == "dedicatedInfoType":
                nas_info_list.append(initial_dict[key][1])
            elif key == "dedicatedInfoNASList":
                for e in initial_dict[key]:
                    nas_info_list.append(e)
            #if str.upper(type(initial_dict[key]).__name__) == "INT":
                #if(initial_dict[key] == 6):
                    #initial_dict[key] += 1
        return

    def parse_tuple(self, container, container_key, nas_info_list, index=0, print_info=True, fuzz=False, row=0, content=0):
        # type: (object, object, list, int, bool,  bool, int, object) -> object
        for i in range(0, len(container[container_key])):
            if print_info:
                print(index * self.sep_char, end='')
            self.recursor(container[container_key], i, nas_info_list, index, print_info=print_info, fuzz=fuzz, row=row, content=content)
            #if str.upper(type(container[container_key][i]).__name__) == "INT":
                #if(container[container_key][i] == 6):
                    #new_tuple = container[container_key][:i] + (container[container_key][i] + 1,) + container[container_key][i+1:]
                    #container[container_key] = new_tuple
        return

    def recursor(self, container, container_key, nas_info_list, index, print_info=True, fuzz=False, row=0, content=0):
        if print_info:
            elem_type = str.upper(type(container[container_key]).__name__)
            print(elem_type, end=' ')
        if isinstance(container[container_key], dict):
            if print_info:
                print("")
            self.parse_dict(container, container_key, nas_info_list, index + 1, print_info=print_info, fuzz=fuzz, row=row, content=content)
        elif isinstance(container[container_key], tuple) or isinstance(container[container_key], list):
            if print_info:
                print("")
            self.parse_tuple(container, container_key, nas_info_list, index + 1, print_info=print_info, fuzz=fuzz, row=row, content=content)
        else:
            if print_info:
                if elem_type == "BYTES":
                    print(container[container_key].hex(), "(", self.counter, ")")
                else:
                    print(container[container_key], "(", self.counter, ")")
            if fuzz and row == self.counter:
                print("FUZZED")
                container[container_key] = content
            self.counter += 1
        return

    def decode_nas(self, data, is_uplink, recursive=True):
        pdu = data
        m = 0
        e = 0
        if is_uplink:
            m, e = parse_NAS_MO(pdu)
        else:
            m, e = parse_NAS_MT(pdu)

        v = m.get_val()
        t = m.to_json()
        self.nas_json.append(t)

        if const.DEBUG_NAS_PRINT:
            #print("[DEBUG] Provided NAS bytes:", pdu)
            #print("[DEBUG] Nas Val:", m)
            print("[DEBUG] Json NAS:", str.upper(type(t).__name__), t.replace("\n", "\n\t"))
        if recursive:
            self.parse_nas(t, is_uplink)

        if const.CORRECT_NAS_TEST:
            assert (e == 0)
            m.reautomate()
            assert (m.get_val() == v)
            m.set_val(v)
            assert (m.to_bytes() == pdu)
            m.from_json(t)
            assert (m.get_val() == v)

    def parse_nas(self, t, is_uplink):
        j = json.loads(t)
        keys = list(j.keys())
        for e in j[keys[0]]:
            inner_keys = list(e.keys())
            if inner_keys == ["NASMessage"]:
                if const.DEBUG_NAS_PRINT:
                    print("\nInner NAS Message:\n")
                self.decode_nas(unhexlify(e["NASMessage"]), is_uplink, False)
        if const.CORRECT_NAS_TEST:
            assert (keys == ["EMMSecProtNASMessage"] or
                    keys == ["EMMIdentityRequest"] or
                    keys == ["EMMAuthenticationRequest"] or
                    keys == ["EMMAuthenticationResponse"] or
                    keys == ["EMMIdentityResponse"])

    def debug_extra(self):
        if const.DEBUG_PDU_PRINT:
            # NOTE: SEMBRA SCRORRETTO
            #print("[DEBUG] Provided PDU\n" + hexlify(self.pdu).hex())
            print("[DEBUG] JSON Format\n" + self.msg_type.to_jer())
            print("[DEBUG] Dict print\n", self.msg_type())

        if const.CORRECT_TEST:
            ret = self.msg_type.to_uper()
            assert (ret == self.pdu)

        if const.WS_TEST:
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