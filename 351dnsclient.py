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


H_1 = "736F"
H_2 = "0100"
H_3 = "0001"    # question count
H_4 = "0000"    # answer rr count
H_5 = "0000"    # authority rr count
H_6 = "0001"    # additional rr count

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

ANS_TYPE_A = 1
ANS_TYPE_DS = 43
ANS_TYPE_RRSIG = 46
ANS_TYPE_DNSKEY = 48
ANS_TYPE_NSEC3 = 50

TIME_OUT_SEC = 5
ANS_OFFSET = 20
HEAD_LEN = 24


def send_query():
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

    if record.upper() not in Q_TYPE_STRING:
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
        name_bin = name_bin + int_to_hex(len(n)) + str_to_hex(n)

    name_bin = name_bin + Z_BYTE

    header = (H_1 + H_2 + H_3 + H_4 + H_5 + H_6)
    question = name_bin + record_hex + Q_CLASS

    add_rr = OPT_NAME + OPT_TYPE + OPT_CLASS + OPT_TTL + OPT_RDLEN

    msg = binascii.unhexlify((header + question + add_rr).replace("\n", ""))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(0)
    timed_out = False
    erred_out = False
    is_query_response = False
    resp = []

    try:
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

    parsed_response = parse_response(question, resp[0])
    key_validation(parsed_response)
    # get a response for com
    # parse that
    # key validate it
    # if that's good, get a response for root
    # parse that
    # key validate that
    # if that's good, we good. Print out all that shit
    print()


def key_validation(pr):
    """
    Takes a response, checks the keys to validate them.
    Also checks to see if the sig is still valid with it's expiration dates.
    :param pr: the parsed response
    :return: True if the response is validated,
    prints error message otherwise.
    """
    # Check the sig_inc and sig_exp to make sure it's still valid
    # If so, move on to check the keys
    h = ''
    verified = False
    for r in pr:
        if r['record_type'] == 'RRSIG':
            if r['algorithm'] == '8':
                h = hashlib.sha3_256(r['signature'].encode('utf-8')).hexdigest()
            elif r['algorithm'] == '10':
                h = hashlib.sha3_512(r['signature'].encode('utf-8')).hexdigest()
            elif r['algorithm'] == '5':
                h = hashlib.sha1(r['signature'].encode('utf-8')).hexdigest()
            else:
                # This'll need to be more detailed error message
                print("Incorrect RRSIG Algorithm")
    # check the hash and compare to all the DS record's digest
    for r in pr:
        if r['record_type'] == "DS":
            if h == r['digest']:
                verified = True
    if verified:
        return True
    else:
        # Print out error with error type as found above (invalid-rrsig, etc)
        print("not verified")


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

        # if 0 <= int(wrd, 16) <= 31:
        #     s_list.append(".")
        # else:
        #     s_list.append(chr(int(wrd, 16)))

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
    :param q_type: question type sent in query
    :param q: query string
    :param r: response string
    :return: Array of parsed responses as dictionaries
    """
    parsed_response = []
    hex_str = str(binascii.hexlify(r))[1:-1]
    q_len = len(q)
    head_bin_list = []

    # dump_hex(hex_str[1:])

    # print("hex str: " + hex_str)

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
            # print("Resource record type " + record_type + "\t")
        else:
            record_type = ""
            # print("Resource record type hex: " + ans_type)

        end_index = start_index + 2 * ans_len
        ans_hex = hex_str[start_index:end_index]
        ans_bin = hex_to_bin_list(ans_hex)
        ans_as_bin_str = arr_to_str(ans_bin)

        if ans_type == Q_TYPE_HEX[1]:
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

            parsed_response.append({
                "record_type": record_type,
                "key_tag": str(key_tag),
                "algorithm": str(alg),
                "digest_type": str(digest_type),
                "digest": digest_hex_str
            })

            # print("Key tag: " + str(key_tag))
            # print("Algorithm: " + str(alg))
            # print("Digest type: " + str(digest_type))
            # print("Digest: " + digest_hex_str)
        elif ans_type == Q_TYPE_HEX[2]:
            # RRSIG Record
            type_covered = int(ans_as_bin_str[0:16], 2)
            alg = int(ans_as_bin_str[16:24], 2)
            labels = int(ans_as_bin_str[24:32], 2)
            ttl = int(ans_as_bin_str[32:64], 2)
            sig_exp = int(ans_as_bin_str[64:96], 2)
            sig_inc = int(ans_as_bin_str[96:128], 2)
            key_tag = int(ans_as_bin_str[128:144], 2)
            [sig_name, sig_index] = get_name_hex_and_next_index(ans_as_bin_str[144:])
            sig = bin_str_to_hex_str(ans_as_bin_str[sig_index + 144:])

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
                "sig_as_base64": str(base64.b64encode(bytes(sig, "utf-8")))[2:-1]
            })

            # print("Type covered: " + str(type_covered))
            # print("Algorithm: " + str(alg))
            # print("Labels: " + str(labels))
            # print("TTL: " + str(ttl))
            # print("Signature expiration: " + str(sig_exp))
            # print("Signature inception: " + str(sig_inc))
            # print("Key tag: " + str(key_tag))
            # print("Signature name: " + sig_name)
            # print("Signature: " + sig)
        elif ans_type == Q_TYPE_HEX[3]:
            # NSEC Record
            [next_domain, type_bit_maps_index] = get_name_hex_and_next_index(ans_as_bin_str)
            type_bit_maps = bin_str_to_hex_str(ans_as_bin_str[type_bit_maps_index:])

            parsed_response.append({
                "record_type": record_type,
                "next_domain": next_domain,
                "type_bit_maps": type_bit_maps
            })

            # print("Next domain: " + next_domain)
            # print("Type bit maps: " + type_bit_maps)
        elif ans_type == Q_TYPE_HEX[4]:
            # DNSKEY Record
            flags = ans_as_bin_str[0:16]
            protocol = int(ans_as_bin_str[16:24], 2)
            alg = int(ans_as_bin_str[24:32], 2)
            pub_key = bin_str_to_hex_str(ans_as_bin_str[32:])

            parsed_response.append({
                "record_type": record_type,
                "flags": flags,
                "protocol": str(protocol),
                "algorithm": str(alg),
                "public_key": str(pub_key)
            })

            # print("Flags: " + flags)
            # print("Protocol: " + str(protocol))
            # print("Algorithm: " + str(alg))
            # print("Public key: " + str(pub_key))
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

            # print("Hash Algorithm: " + str(hash_alg))
            # print("Flags: " + flags)
            # print("Iterations: " + str(iterations))
            # print("Salt: " + salt)
            # print("Next hash owner name: " + next_hash_owner_name)
            # print("Type bit maps: " + type_bit_maps)
        else:
            pass
            # print("Unrecognized response type.")
            # print("Binary dump: ")
            # print(ans_as_bin_str)
            # print("Hex dump: ")
            # print(bin_str_to_hex_str(ans_as_bin_str))

        # print()
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

            # hex_str = hex_str + next_hex + " "
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
    send_query()
