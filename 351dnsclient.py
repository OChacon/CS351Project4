"""
Starbuck Beagley & Oscar Chacon
CSCI-351

Project 4: Simple DNSSEC Client
"""


import binascii
import sys
import socket
import select
import math
import base64
import hashlib
# from Crypto.PublicKey import RSA
# from Crypto.Signature import PKCS1_v1_5
# from Crypto.Hash import SHA256
# from base64 import b64decode
import time


H_1 = "736F"
H_2 = "0100"
H_3 = "0001"    # question count
H_4 = "0000"    # answer rr count
H_5 = "0000"    # authority rr count
H_6 = "0001"    # additional rr count

Q_TYPE_VALID_INPUTS = [
    "A",
    "DS",
    "DNSKEY"
]

Q_TYPE_STRING = [
    "A",
    "DS",
    "RRSIG",
    "NSEC",
    "DNSKEY",
    "NSEC3"
]

Q_TYPE_HEX = [
    "0001",
    "002B",
    "002E",
    "002F",
    "0030",
    "0032"
]

OPT_NAME = "010000"
OPT_TYPE = "0029"
OPT_CLASS = "F500"
OPT_TTL = "00008000"
OPT_RDLEN = "0000"

Q_CLASS = "0001"
Z_BYTE = "00"

ANS_TYPE_INT = [
    1,
    43,
    46,
    47,
    48,
    50
]

DNSKEY_ALGS = [
    "DELETE",
    "RSAMD5",
    "DH",
    "DSA",
    "",
    "RSASHA1",
    "DSA-NSEC3-SHA1",
    "RSASHA1-NSEC3-SHA1",
    "RSASHA256",
    "",
    "RSASHA512",
    "",
    "ECC-GOST",
    "ECDSAP256SHA256",
    "ECDSAP384SHA384",
    "ED25519",
    "ED448"
]

ANS_TYPE_A = 1
ANS_TYPE_DS = 43
ANS_TYPE_RRSIG = 46
ANS_TYPE_DNSKEY = 48
ANS_TYPE_NSEC3 = 50

TIME_OUT_SEC = 5
ANS_OFFSET = 20
HEAD_LEN = 24


def main():
    """
        Main function. Parses command line parameters, constructs
        and sends query, interprets and displays response.
        :return: None
    """
    args = sys.argv
    args_len = len(args)
    server = ""
    name = ""
    record = ""
    record_hex = ""

    if args_len == 4:
        server = args[1]
        name = args[2]
        record = args[3]
    else:
        usage()
        exit(0)

    port = 53

    if server[0] == "@":
        server = server[1:]
    else:
        usage()
        exit(0)

    if record.upper() not in Q_TYPE_VALID_INPUTS:
        usage()
        exit(0)
    else:
        record = record.upper()
        record_hex = Q_TYPE_HEX[Q_TYPE_STRING.index(record)]

    if ":" in server:
        server_port = server.split(":")
        server = str(server_port[0])

        try:
            port = int(server_port[1])
        except ValueError:
            usage()
            exit(0)

    if "." not in name or len(server.split(".")) != 4:
        usage()
        exit(0)

    name_list = name.split(".")
    name_bin = ""

    if args_len == 4 and name_list[0] == "www":
        name_list.pop(0)

    for n in name_list:
        if n != "":
            name_bin = name_bin + int_to_hex(len(n)) + str_to_hex(n)

    name_bin = name_bin + Z_BYTE

    header = (H_1 + H_2 + H_3 + H_4 + H_5 + H_6)
    question = name_bin + record_hex + Q_CLASS

    add_rr = OPT_NAME + OPT_TYPE + OPT_CLASS + OPT_TTL + OPT_RDLEN

    msg = binascii.unhexlify((header + question + add_rr).replace("\n", ""))

    response = send_query(server, msg, port, question, True)
    parsed_response = parse_response(response[0], response[1])

    record_hex = Q_TYPE_HEX[4]
    question = name_bin + record_hex + Q_CLASS
    msg = binascii.unhexlify((header + question + add_rr).replace("\n", ""))
    dnskey_response = send_query(server, msg, port, question, False)
    dnskey_parsed_response = parse_response(dnskey_response[0], dnskey_response[1])

    # key_validation(parsed_response, dnskey_parsed_response, name_bin, record)

    print_results(name, record, parsed_response)


def send_query(server, msg, port, question, dump):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(0)
    timed_out = False
    erred_out = False
    is_query_response = False
    resp = []

    try:
        if dump:
            dump_packet(msg)
        sock.sendto(msg, (server, port))

        while not timed_out and not is_query_response:
            ready = select.select([sock], [], [], TIME_OUT_SEC)

            if ready[0]:
                resp = sock.recvfrom(4096)
                is_query_response = is_dns_response(resp[0])

            if not resp:
                timed_out = True
    except socket.gaierror as e:
        print_err(e.strerror)
        timed_out = False
        erred_out = True
    finally:
        sock.close()

    if timed_out:
        print("NORESPONSE")
        exit(0)
    elif erred_out:
        exit(0)

    return question, resp[0]


# key_validation is not fully functional
def key_validation(pr, dnskey_pr, name_bin, record):
    """
    Takes a response, checks the keys to validate them.
    Also checks to see if the sig is still valid with it's expiration dates.
    :param pr: the parsed response
    :param dnskey_pr: the dnskey parsed response
    :param name_bin: the owner name
    :param record: the specific record that needs to be verified
    :return: True if the response is validated,
    prints error message otherwise.
    """
    expired = True
    verified = False
    ds_count = 0
    rrsig_count = 0
    a_count = 0
    dnskey_count = 0
    dnskey_digest = []

    if record == "DS":
        for r in dnskey_pr:
            if r['record_type'] == 'DNSKEY':
                # build each RDATA
                f = bin_str_to_hex_str(r['flags']).replace(" ", "")
                p = int_to_hex(int(r['protocol']))
                a = int_to_hex(int(r['algorithm']))
                pk = r['public_key'].replace(" ", "")
                rdata = f + p + a + pk
                # make the digest and store it
                d = name_bin + rdata
                dnskey_digest.append(hasher(r['algorithm'], d))

        for r in pr:
            if r['record_type'] == 'RRSIG':
                rrsig_count = rrsig_count + 1
                # Check the sig_inc and sig_exp to make sure it's still valid
                cur_time = time.time()
                if int(r['sig_inc']) < cur_time < int(r['sig_exp']):
                    expired = False

        # check the hash and compare to all the DS record's digest
        for r in pr:
            if r['record_type'] == "DS":
                ds_count = ds_count + 1
                d = r['digest'].replace(" ", "")
                for e in dnskey_digest:
                    if e == d:
                        verified = True

        if ds_count == 0:
            print("ERROR\tMISSING-DS\n")
            exit(0)
        elif rrsig_count == 0:
            print("ERROR\tMISSING-RRSIG\n")
            exit(0)
        elif expired:
            print("ERROR\tEXPIRED-RRSIG\n")
            exit(0)
        elif not verified:
            print("ERROR\tINVALID-RRSIG\n")
            # exit(0)
        else:
            print("ERROR\tNONE\n")
            exit(0)

    elif record == "A":
        rdata = ''
        rr = ''
        ottl = ''
        for r in pr:
            if r['record_type'] == "RRSIG":
                # Build the rdata
                tc = r['type_covered']
                a = r['algorithm']
                l = r['labels']
                ottl = r['ttl']
                sig_exp = r['sig_exp']
                sig_inc = r['sig_inc']
                kt = r['key_tag']
                rdata = tc + a + l + ottl + sig_exp + sig_inc + kt + name_bin

        for r in pr:
            # Build RR
            if r['record_type'] == "A":
                t = r['r_t']
                c = r['class']
                ttl = ottl
                dl = r['data_len']
                a = (r['ip']).split(".")
                addr = ''
                for x in a:
                    addr = addr + int_to_hex(int(x))
                rr = name_bin + t + c + ttl + dl + addr

        digest = rdata + rr
        # get the sig verifier function, feed it the digest and the rrsig's sig

    elif record == "DNSKEY":
        for r in pr:
            if r['record_type'] == 'DNSKEY':
                dnskey_count = dnskey_count + 1
            elif r['record_type'] == 'RRSIG':
                rrsig_count = rrsig_count + 1
                # Check the sig_inc and sig_exp to make sure it's still valid
                cur_time = time.time()
                if int(r['sig_inc']) < cur_time < int(r['sig_exp']):
                    expired = False

        if dnskey_count == 0:
            print("ERROR\tMISSING-DNSKEY\n")
            exit(0)
        elif rrsig_count == 0:
            print("ERROR\tMISSING-RRSIG\n")
            exit(0)
        elif expired:
            print("ERROR\tEXPIRED-RRSIG\n")
            exit(0)
        elif not verified:
            print("ERROR\tINVALID-RRSIG\n")
            # exit(0)
        else:
            print("ERROR\tNONE\n")
            exit(0)


def hasher(algo, s):
    """
    Takes a specific algo and the string to be hashed
    :param algo: the specific hashing function to use
    :param s: the string to be hashed
    :return: a hash according to the specific algo to use
    """
    if algo == '8':
        x = binascii.unhexlify(s)
        return hashlib.sha256(x).hexdigest()
    elif algo == '10':
        x = binascii.unhexlify(s)
        return hashlib.sha512(x).hexdigest()
    elif algo == '5':
        x = binascii.unhexlify(s)
        return hashlib.sha1(x).hexdigest()


def dump_packet(p):
    """
    Displays query hex and domain name
    :param p: DNS query string
    :return: None
    """
    s_list = []
    h_list = []
    h_str = str(binascii.hexlify(p))[2:-1]
    h_len = len(h_str)

    for i in range(0, h_len, 2):
        wrd = h_str[i:i + 2]
        h_list.append(wrd)

        wrd_as_int = int(wrd, 16)

        if wrd_as_int == 45 or \
            (47 < wrd_as_int < 58) or \
            (64 < wrd_as_int < 91) or \
            (96 < wrd_as_int < 123):
            s_list.append(chr(int(wrd, 16)))
        else:
            s_list.append(".")

    wrd_cnt = len(h_list)
    lines_cnt = int(math.floor(wrd_cnt / 16) + 1)

    if wrd_cnt % 16 == 0:
        lines_cnt -= 1

    for i in range(16 - (wrd_cnt % 16)):
        h_list.append("  ")
        s_list.append("  ")

    print("Packet dump:")

    for i in range(0, lines_cnt):
        dump_str = "[00" + str(i) + "0] "
        list_i_start = i * 16
        list_i_end = (i + 1) * 16

        for j in range(list_i_start, list_i_end):
            if j % 8 == 0:
                dump_str += "  "

            dump_str += str(h_list[j]) + " "

        for j in range(list_i_start, list_i_end):
            if j % 8 == 0:
                dump_str += "  "

            dump_str += str(s_list[j]) + " "

        print(dump_str)
    print()


def dump_hex(h):
    """
    Dumps raw hex string for debugging
    :param h: hex string
    :return: None
    """
    h_len = len(h)

    for i in range(0, h_len):
        print(h[i], end="")

        if (i + 1) % 2 == 0:
            print(" ", end="")

    print()


def parse_response(q, r):
    """
    Parses server response to query
    :param q: query string
    :param r: response string
    :return: Array of parsed responses as dictionaries
    """
    parsed_response = []
    hex_str = str(binascii.hexlify(r))[1:-1]
    q_len = len(q)
    head_bin_list = []

    for i in range(5, HEAD_LEN + 1, 4):
        head_bin_list.append(hex_to_bin_list(hex_str[i:i + 4]))

    r_code = head_bin_list[0][1][4:]
    ans_count = int(head_bin_list[2][0] + head_bin_list[2][1], 2)
    auth_count = int(head_bin_list[3][0] + head_bin_list[3][1], 2)
    add_count = int(head_bin_list[4][0] + head_bin_list[4][1], 2)

    if r_code != "0000":
        if int(r_code, 2) == 3:
            print("NOTFOUND")
        else:
            print_err("RCODE: " + str(int(r_code, 2)))

        return

    for i in range(HEAD_LEN + 1, HEAD_LEN + q_len + 1):
        if hex_str[i].lower() != q[i - (HEAD_LEN + 1)].lower():
            print_err("Response question does not match query question")
            return

    ans_index = HEAD_LEN + q_len + 1

    for i in range(0, ans_count + auth_count + add_count):
        ans_type = hex_str[ans_index + 4:ans_index + 8].upper()
        rd_index = ans_index + ANS_OFFSET
        start_index = rd_index + 4
        ans_len = int(hex_str[rd_index:start_index], 16)

        if ans_type in Q_TYPE_HEX:
            record_type = Q_TYPE_STRING[Q_TYPE_HEX.index(ans_type)]
        else:
            record_type = ""

        end_index = start_index + 2 * ans_len
        ans_hex = hex_str[start_index:end_index]
        ans_bin = hex_to_bin_list(ans_hex)
        ans_as_bin_str = arr_to_str(ans_bin)
        rdata_for_hash = hex_str[ans_index:end_index].replace(" ", "")

        if ans_type == Q_TYPE_HEX[0]:
            # A Record
            n = q[:len(q) - 8]
            t = hex_str[ans_index + 4: ans_index + 8].upper()
            c = hex_str[ans_index + 8:ans_index + 12].upper()
            ttl = hex_str[ans_index + 12:ans_index + 20].upper()
            data_len = hex_str[ans_index + 20: ans_index + 24].upper()
            ip_1 = str(int(hex_str[rd_index + 4: rd_index + 6], 16))
            ip_2 = str(int(hex_str[rd_index + 6: rd_index + 8], 16))
            ip_3 = str(int(hex_str[rd_index + 8: rd_index + 10], 16))
            ip_4 = str(int(hex_str[rd_index + 10: rd_index + 12], 16))
            ip_full = ip_1 + "." + ip_2 + "." + ip_3 + "." + ip_4

            parsed_response.append({
                "name": n,
                "record_type": record_type,
                "r_t": t,
                "class": c,
                "ttl": ttl,
                "data_len": data_len,
                "ip": ip_full
            })
        elif ans_type == Q_TYPE_HEX[1]:
            # DS Record
            key_tag = int(ans_as_bin_str[0:16], 2)
            alg = int(ans_as_bin_str[16:24], 2)
            digest_type = int(ans_as_bin_str[24:32], 2)

            if digest_type == 1:
                digest_bin = ans_as_bin_str[32:20 * 8 + 32]
            elif digest_type == 2:
                digest_bin = ans_as_bin_str[32:32 * 8 + 32]
            else:
                print("Skipping resource record " + str(i) + ". Unrecognized digest type.")
                continue

            digest_hex_str = bin_str_to_hex_str(digest_bin)
            digest_as_int = int(digest_bin, 2)

            parsed_response.append({
                "record_type": record_type,
                "key_tag": str(key_tag),
                "algorithm": str(alg),
                "digest_type": str(digest_type),
                "digest": digest_hex_str,
                "digest_as_int": digest_as_int,
                "rdata_for_hash": rdata_for_hash
            })
        elif ans_type == Q_TYPE_HEX[2]:
            # RRSIG Record
            type_covered = bin_str_to_hex_str(ans_as_bin_str[0:16]).replace(" ", "")
            alg = bin_str_to_hex_str(ans_as_bin_str[16:24]).replace(" ", "")
            labels = bin_str_to_hex_str(ans_as_bin_str[24:32]).replace(" ", "")
            ttl = bin_str_to_hex_str(ans_as_bin_str[32:64]).replace(" ", "")
            sig_exp = bin_str_to_hex_str(ans_as_bin_str[64:96]).replace(" ", "")
            sig_inc = bin_str_to_hex_str(ans_as_bin_str[96:128]).replace(" ", "")
            key_tag = bin_str_to_hex_str(ans_as_bin_str[128:144]).replace(" ", "")
            [sig_name, sig_index] = get_name_hex_and_next_index(ans_as_bin_str[144:])
            sig = bin_str_to_hex_str(ans_as_bin_str[sig_index + 144:])
            sig_as_base64 = str(base64.b64encode(bytes(sig, "utf-8")))[2:-1]
            sig_as_int = str_to_int(sig_as_base64)

            parsed_response.append({
                "record_type": record_type,
                "type_covered": str(type_covered),
                "algorithm": str(alg),
                "labels": str(labels),
                "ttl": str(ttl),
                "sig_exp": str(sig_exp),
                "sig_inc": str(sig_inc),
                "key_tag": str(key_tag),
                "sig_name": sig_name,
                "signature": sig,
                "sig_as_base64": sig_as_base64,
                "sig_as_int": sig_as_int,
                "rdata_for_hash": rdata_for_hash
            })
        elif ans_type == Q_TYPE_HEX[3]:
            # NSEC Record
            [next_domain, type_bit_maps_index] = get_name_hex_and_next_index(ans_as_bin_str)
            type_bit_maps = bin_str_to_hex_str(ans_as_bin_str[type_bit_maps_index:])

            parsed_response.append({
                "record_type": record_type,
                "next_domain": next_domain,
                "type_bit_maps": type_bit_maps
            })
        elif ans_type == Q_TYPE_HEX[4]:
            # DNSKEY Record
            flags = ans_as_bin_str[0:16]
            protocol = int(ans_as_bin_str[16:24], 2)
            alg = int(ans_as_bin_str[24:32], 2)
            alg_name = DNSKEY_ALGS[alg]
            pub_key = bin_str_to_hex_str(ans_as_bin_str[32:])
            pub_key_as_base64 = str(base64.b64encode(bytes(pub_key, "utf-8")))[2:-1]
            key_type_num = int(flags, 2)
            key_type_str = "KSK"

            if key_type_num == 256:
                key_type_str = "ZSK"

            [key_exponent, key_mod, key_test] = get_key_exponent_and_key(pub_key.replace(" ", ""))

            parsed_response.append({
                "record_type": record_type,
                "flags": flags,
                "key_type_num": str(key_type_num),
                "key_type_str": str(key_type_str),
                "protocol": str(protocol),
                "algorithm": str(alg),
                "alg_name": alg_name,
                "public_key": str(pub_key),
                "pub_key_as_base64": pub_key_as_base64,
                "key_exponent": key_exponent,
                "key_mod": key_mod,
                "key_mod_test": key_test
            })
        elif ans_type == Q_TYPE_HEX[5]:
            # NSEC3 Record
            hash_alg = int(ans_as_bin_str[0:8], 2)
            flags = ans_as_bin_str[8:16]
            iterations = int(ans_as_bin_str[16:32], 2)
            salt_len = int(ans_as_bin_str[32:40], 2)
            hash_len_index = salt_len * 4
            salt = bin_str_to_hex_str(ans_as_bin_str[40:hash_len_index])
            hash_len = int(ans_as_bin_str[hash_len_index:hash_len_index + 8], 2)
            type_bit_maps_index = hash_len_index + 8 + hash_len * 4
            next_hash_owner_name = bin_str_to_hex_str(ans_as_bin_str[hash_len_index + 8:type_bit_maps_index])
            type_bit_maps = bin_str_to_hex_str(ans_as_bin_str[type_bit_maps_index:])

            parsed_response.append({
                "record_type": record_type,
                "hash_algorithm": str(hash_alg),
                "flags": flags,
                "iterations": str(iterations),
                "salt": salt,
                "next_hash_owner_name": next_hash_owner_name,
                "type_bit_maps": type_bit_maps
            })

        ans_index = end_index

    return parsed_response


def int_to_hex(i):
    """
    Translates small integer to hexadecimal
    :param i: integer
    :return: hexadecimal string
    """
    hex_i = hex(i).replace("0x", "")

    if len(hex_i) < 2:
        hex_i = "0" + hex_i

    return hex_i


def str_to_hex(s):
    """
    Translates character string to hexadecimal string
    :param s: string
    :return: hexadecimal string
    """
    hex_s = ""

    for c in s:
        h = hex(ord(c)).replace("0x", "")

        if len(h) < 2:
            h = "0" + h

        hex_s += h

    return hex_s


def hex_to_bin_list(h_str):
    """
    Translates hexadecimal string to list of binary strings
    :param h_str: hexadecimal string
    :return: binary string list
    """
    bin_list = []
    bin_list_full = []

    for h in h_str:
        b = str(bin(int(h, 16)))[2:]

        while len(b) < 4:
            b = "0" + b

        bin_list.append(b)

    bin_list_len = len(bin_list)

    for i in range(0, bin_list_len, 2):
        b = bin_list[i]

        if (i + 1) < bin_list_len:
            b = b + bin_list[i + 1]
        else:
            b = "0000" + b

        bin_list_full.append(b)

    return bin_list_full


def bin_str_to_hex_str(b_str):
    """
    Translates binary string to hex string
    :param b_str: binary string
    :return: hex string
    """
    b_len = len(b_str)
    byte_count = int(b_len / 8)
    hex_str = ""

    if b_len % 8 != 0:
        print("Length of binary sent to bin_str_to_hex_str is " + str(b_len))
        return ""

    for i in range(0, byte_count):
        start = i * 8
        hex_int = hex(int(b_str[start:start + 8], 2))
        hex_str_part = str(hex_int[2:])

        if len(hex_str_part) == 1:
            hex_str_part = "0" + hex_str_part

        hex_str = hex_str + hex_str_part + " "

    return hex_str


def get_name_hex_and_next_index(bin_str):
    """
    Gets name from beginning of binary string and returns name and final index
    :param bin_str: binary string
    :return: name and final index
    """
    word_len = int(bin_str[0:8], 2) * 8
    start_index = 8
    final_index = start_index + word_len
    keep_going = True
    hex_str = ""

    while keep_going:
        for i in range(start_index, final_index, 8):
            next_hex = str(hex(int(bin_str[i:i + 8], 2))[2:])

            if len(next_hex) == 1:
                next_hex = "0" + next_hex

            hex_str = hex_str + chr(int(next_hex, 16))

        next_bin = bin_str[final_index:final_index + 8]

        if len(next_bin) == 8:      # stop if find a space character
            word_len = int(next_bin, 2)

            if word_len == 0:
                keep_going = False
                final_index = final_index + 8
            else:
                hex_str = hex_str + "."
                start_index = final_index + 8
                final_index = start_index + word_len * 8
        else:
            keep_going = False

    return [hex_str, final_index]


def get_key_exponent_and_key(pk):
    """
    Gets key exponent and modulus
    :param pk: string
    :return: exponent and modulus
    """
    exp = int(pk[2:8], 16)
    k = str_to_int(pk[8:])
    k_int = int(pk[8:], 16)

    return [exp, k, k_int]


def str_to_int(s):
    """
    Translates string to int
    :param s: string
    :return: int
    """
    new_int = 0

    for c in s:
        new_int = new_int * 256 + ord(c)

    return new_int


def arr_to_str(arr):
    """
    Creates string from array of strings
    :param arr: array of strings
    :return: combined string
    """
    the_string = ""

    for a in arr:
        the_string = the_string + a

    return the_string


def get_name_by_offset(hex_str, offset):
    """
    Gets domain name at given offset in DNS response
    :param hex_str: DNS response as hexadecimal string
    :param offset: offset in DNS string
    :return: domain name string
    """
    name = ""
    name_len = int(hex_str[offset:offset + 2], 16)

    try:    # workaround for extra space at end of hexadecimal string
        while name_len != 0:
            i = offset + 2
            end_index = i + (2 * name_len)

            while i < end_index:
                int_val = int(hex_str[i:i + 2], 16)

                if int_val < 32:
                    name += "."
                else:
                    name += chr(int_val)

                i += 2

            offset = end_index
            name_len = int(hex_str[offset:offset + 2], 16)

            if name_len > 0:
                name += "."
    except ValueError:
        pass

    return name


def is_dns_response(s):
    """
    Checks whether DNS response has valid ID and has response type flag set
    :param s: DNS response string
    :return: True if valid, False otherwise
    """
    hex_list = str(s).split("\\x")

    if int(str_to_hex(hex_list[0][2:4]), 16) != int(H_1, 16):
        return False
    elif str(hex_to_bin_list(hex_list[1])[0])[0] != "1":
        return False
    else:
        return True


def print_results(url, q_type, results):
    """
    Prints results
    :param url: queried url
    :param q_type: query type
    :param results: results
    :return: None
    """
    url_tab_count = int(len(url) / 4)
    sig_indent = "\t\t\t"

    for i in range(0, url_tab_count):
        sig_indent = sig_indent + "\t"

    url_str = url + "\t\t"

    if q_type == Q_TYPE_VALID_INPUTS[0]:
        for r in results:
            if r["record_type"] == Q_TYPE_STRING[0]:
                print(url_str, end="")
                print("IN A " + r["ip"])
            elif r["record_type"] == Q_TYPE_STRING[2]:
                print(url_str, end="")
                print("IN RRSIG ", end="")
                print(Q_TYPE_STRING[ANS_TYPE_INT.index(int(r["type_covered"], 16))] + " ", end="")
                print(str(int(r["labels"], 16)) + " ", end="")
                print(str(int(r["ttl"], 16)) + " (")
                print_digest_or_base64(r["sig_as_base64"], sig_indent)
    elif q_type == Q_TYPE_VALID_INPUTS[1]:
        for r in results:
            if r["record_type"] == Q_TYPE_STRING[1]:
                print(url_str, end="")
                print("IN DS ", end="")
                print(r["key_tag"] + " ", end="")
                print(r["algorithm"] + " ", end="")
                print(r["digest_type"] + " (")
                print_digest_or_base64(r["digest"], sig_indent)
            elif r["record_type"] == Q_TYPE_STRING[2]:
                print(url_str, end="")
                print("IN RRSIG DS ", end="")
                print(str(int(r["algorithm"], 16)) + " ", end="")
                print(Q_TYPE_STRING[ANS_TYPE_INT.index(int(r["type_covered"], 16))] + " ", end="")
                print(str(int(r["labels"], 16)) + " ", end="")
                print(str(int(r["ttl"], 16)) + " (")
                print(sig_indent, end="")
                print(str(int(r["sig_exp"], 16)) + " ", end="")
                print(str(int(r["sig_inc"], 16)) + " ", end="")
                print(str(int(r["key_tag"], 16)) + " ", end="")
                print(r["sig_name"] + " ")
                print_digest_or_base64(r["sig_as_base64"], sig_indent)
    elif q_type == Q_TYPE_VALID_INPUTS[2]:
        for r in results:
            if r["record_type"] == Q_TYPE_STRING[4]:
                print(url_str, end="")
                print("IN DNSKEY ", end="")
                print(r["key_type_num"] + " ", end="")
                print(r["protocol"] + " ", end="")
                print(r["algorithm"] + " (")
                print_digest_or_base64(r["public_key"], sig_indent)
                print(sig_indent + "; ", end="")
                print(r["key_type_str"] + "; ", end="")
                print("alg = " + r["alg_name"] + "; ")
            elif r["record_type"] == Q_TYPE_STRING[2]:
                print(url_str, end="")
                print("IN RRSIG DNSKEY ", end="")
                print(str(int(r["algorithm"], 16)) + " ", end="")
                print(str(int(r["labels"], 16)) + " ", end="")
                print(str(int(r["ttl"], 16)) + " (")
                print(sig_indent, end="")
                print(str(int(r["sig_exp"], 16)) + " ", end="")
                print(str(int(r["sig_inc"], 16)) + " ", end="")
                print(str(int(r["key_tag"], 16)) + " ", end="")
                print(r["sig_name"] + " ")
                print_digest_or_base64(r["sig_as_base64"], sig_indent)


def print_digest_or_base64(strng, indent):
    """
    Prints digest or base64 string
    :param strng: string to print
    :return: None
    """
    stripped_string = strng.replace(" ", "")
    length = len(stripped_string)

    if length < 45:
        print(indent + stripped_string + " )")
    else:
        print(indent + stripped_string[:44])

        if length > 88:
            print(indent + "[ ... ]")
            print(indent + stripped_string[length - 44:] + " )")
        else:
            print(indent + stripped_string[44:] + " )")


def print_err(e):
    """
    Prints error
    :param e: error string to print
    :return: None
    """
    print("ERROR\t" + e)


def usage():
    """
    Displays usage information
    :return: None
    """
    print("Usage: 351dnsclient @<server:port> <domain-name> <record>")
    print("\tserver (Required) The IP address of the DNS server, in a.b.c.d format.")
    print("\tport (Optional) The UDP port number of the DNS server. Default value: 53.")
    print("\tdomain-name (Required) The name to query for.")
    print("\trecord (Required) The DNS record to query for, which can be either:")
    print("\t\tA: A records")
    print("\t\tDNSKEY: DNSKEY records")
    print("\t\tDS: DS records")
    print("\t\tNSEC3: NSEC3 records")


if __name__ == "__main__":
    main()
