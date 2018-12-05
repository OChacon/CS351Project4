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


H_1 = "736F"
H_2 = "0100"
H_3 = "0001"
H_4 = "0000"
H_5 = "0000"
H_6 = "0000"
Q_TYPE_A = "0001"
Q_TYPE_NS = "0002"
Q_TYPE_MX = "000F"
Q_CLASS = "0001"
Z_BYTE = "00"

ANS_TYPE_A = 1
ANS_TYPE_NS = 2
ANS_TYPE_CNAME = 5
ANS_TYPE_MX = 15
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
    q_type = Q_TYPE_A

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

    if record != "A" and record != "DNSKEY" and record != "DS":
        usage()
        exit(0)

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
    question = name_bin + q_type + Q_CLASS
    msg = binascii.unhexlify((header + question).replace("\n", ""))

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

    print_response(q_type, question, resp[0])


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

        if 0 <= int(wrd, 16) <= 31:
            s_list.append(".")
        else:
            s_list.append(chr(int(wrd, 16)))

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


def print_response(q_type, q, r):
    """
    Prints server response to query
    :param q_type: question type sent in query
    :param q: query string
    :param r: response string
    :return: None
    """
    hex_str = str(binascii.hexlify(r))[1:]
    q_len = len(q)
    head_bin_list = []

    for i in range(5, HEAD_LEN + 1, 4):
        head_bin_list.append(hex_to_bin_list(hex_str[i:i + 4]))

    r_code = head_bin_list[0][1][4:]
    ans_count = int(head_bin_list[2][0] + head_bin_list[2][1], 2)
    auth_count = int(head_bin_list[3][0] + head_bin_list[3][1], 2)
    add_count = int(head_bin_list[4][0] + head_bin_list[4][1], 2)
    is_auth = int(head_bin_list[0][0][5])

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
        should_print = True
        ans_type = int(hex_str[ans_index + 4:ans_index + 8], 16)

        byte_1 = hex_to_bin_list(hex_str[ans_index:ans_index + 2])[0][2:]
        byte_2 = hex_to_bin_list(hex_str[ans_index + 2:ans_index + 4])[0]
        d_name_offset = (int(byte_1 + byte_2, 2) - 12) * 2
        d = get_name_by_offset(q + hex_str[1:], d_name_offset)

        rd_index = ans_index + ANS_OFFSET
        ans_len = int(hex_str[rd_index:rd_index + 4], 16)
        out_str = ""

        if ans_type == ANS_TYPE_A and q_type == Q_TYPE_A:
            ip_1 = str(int(hex_str[rd_index + 4: rd_index + 6], 16))
            ip_2 = str(int(hex_str[rd_index + 6: rd_index + 8], 16))
            ip_3 = str(int(hex_str[rd_index + 8: rd_index + 10], 16))
            ip_4 = str(int(hex_str[rd_index + 10: rd_index + 12], 16))
            ip_full = ip_1 + "." + ip_2 + "." + ip_3 + "." + ip_4
            out_str += "IP   \t" + ip_full

            ans_index = rd_index + 12
        else:
            start_index = rd_index + 6

            if ans_type == ANS_TYPE_NS and q_type == Q_TYPE_NS:
                out_str += "NS   \t"
            elif ans_type == ANS_TYPE_CNAME:
                out_str += "CNAME\t"
            elif ans_type == ANS_TYPE_MX and q_type == Q_TYPE_MX:
                start_index = rd_index + 10
                out_str += "MX\t"
                out_str += str(int(hex_str[rd_index+6:rd_index+8], 16)) + "\t"
            else:
                should_print = False

            end_index = rd_index + 2 * ans_len
            j = start_index

            while j < end_index:
                h = hex_str[j:j + 2]

                if 0 <= int(h, 16) <= 31:
                    out_str += "."
                    j += 2
                else:
                    out_str += chr(int(h, 16))
                    j += 2

            out_str += "." + d
            ans_index = rd_index + 4 + 2 * ans_len

        if should_print:
            if (i < ans_count or i >= int(ans_count) + int(auth_count)) and is_auth != 1:
                print(out_str + "\t <nonauth>")
            else:
                print(out_str + "\t <auth>")


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
    print("\tdomain-name (Required) The DNS record to query for, which can be either:")
    print("\tA: A records")
    print("\tDNSKEY: DNSKEY records")
    print("\tDS: DS records")


if __name__ == "__main__":
    send_query()
