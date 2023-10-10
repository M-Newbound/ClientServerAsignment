"""
author: Martin Newbound (37202364)
23/08/2023

"""


import sys
import socket
import common

SYSTEM_ARGUMENTS = 5

def construct_message_request(magic_number, msg_id, name_length, receiver_length, message_length, payload):
    """
    will construct a byte array which follows the message response format.

    @param magic_number    ->  int         --> the magic number header field
    @param msg_id          ->  int         --> the request id header field
    @param name_length     ->  int         --> the length of the sender's name, in bytes
    @param receiver_length ->  int         --> the length of the receiver's name, in bytes
    @param message_length  ->  int         --> the length of the actual message, in bytes
    @param payload         ->  bytearray   --> the actual message, size should be == to message_length
    
    @returns               -> bytearray    --> the fully constructed message request
    """
    message = bytearray(common.REQUEST_FIXED_HDR_SIZE)

    # loading in data-----------------------------------------------------------------
    common.load_data_into_byte_arr(message, magic_number,      0, 2,   "magic-number")
    common.load_data_into_byte_arr(message, msg_id,            2, 3,   "id")
    common.load_data_into_byte_arr(message, name_length,       3, 4,   "name-len")
    common.load_data_into_byte_arr(message, receiver_length,   4, 5,   "receiver-len")
    common.load_data_into_byte_arr(message, message_length,    5, 7,   "message-len")

    message.extend(payload)
    return message


def deconstruct_message_response_header(response_header):
    """
    deconstruct a message response header bytearray

    @param message ->  bytearray                      --> the message response header to deconstruct
    @returns       ->  (bool, (int, int, int, int))   --> the header as, (verification_flag, (magic_num, id, num_items, more_msgs))

    note: verification flag is true if, and only if, the request header follows expected formatting
    """
    # setup & primary validation checks -----------------------------------------------
    magic_number, response_id, num_items, more_msgs = (0,0,0,0)

    if response_header is None : return package(False)
    if len(response_header) != common.RESPONSE_FIXED_HDR_SIZE  : return package(False)

    package = lambda success : (success, (magic_number, response_id, num_items, more_msgs))

    # data extraction ---------------------------------------------------------------------
    magic_number = common.extract_data_from_byte_arr(response_header, 0, 2, "magic-number")
    response_id  = common.extract_data_from_byte_arr(response_header, 2, 3, "response-id")
    num_items    = common.extract_data_from_byte_arr(response_header, 3, 4, "num-items")
    more_msgs    = common.extract_data_from_byte_arr(response_header, 4, 5, "more-msgs")

    # secondary validation checks ---------------------------------------------------------
    if magic_number != common.MAGIC_NUMBER_VALUE : return package(False)
    if response_id != 3                          : return package(False)
    if more_msgs not in [0, 1]                   : return package(False)

    return package(True)


def get_create_request(username_bytes):
    """
    gets a message request of the 'create' type. Uses the console's input to create this request.

    @param username_bytes -> bytes      --> the username of the client
    @returns              -> bytearray  --> the fully constructed create request
    """

    receiver_name_bytes = None
    contents_bytes = None
    
    # get receiver name --------------------------------------------------------------------
    while True:
        receiver_name_str = input("[MESSAGE SETUP] Enter name of receiver: ")
        receiver_name_bytes = receiver_name_str.encode("utf-8")
        if 0 < len(receiver_name_str) and len(receiver_name_bytes) < 255 : break

        print("[ERROR] provided receiver name must be encodable within 255 bytes, and contain at least one character")

    # get message contents ------------------------------------------------------------------
    while True:
        contents_str = input("[MESSAGE SETUP] Enter message contents: ")
        contents_bytes = contents_str.encode("utf-8")
        if 0 < len(contents_str) and len(contents_bytes) < 65535 : break

        print("[ERROR] provided message contents must be encodable within 65,535 bytes, and contain at least one character")

    # return the message request -------------------------------------------------------------
    payload = bytearray(username_bytes)
    payload.extend(receiver_name_bytes)
    payload.extend(contents_bytes)
    
    return construct_message_request(0xAE73, 0x02, len(username_bytes), len(receiver_name_bytes), len(contents_bytes), payload)


def process_create_request(username_bytes, client_socket, server_addr):
    """
    executes client logic to process a create request

    @param username_bytes -> bytes                             --> the client's username
    @param client_socket  -> socket.socket                     --> the client socket
    @param server_addr    -> from socket.socket.getaddrinfo()  --> the server's address
    @returns              -> None
    """
    # get the request -----------------------------------
    message_request = get_create_request(username_bytes)

    # send request to server ---------------------------
    client_socket.connect(server_addr[0][-1])
    client_socket.sendall(message_request)

    # log to console -----------------------------------
    print("sending message request to server")


def process_read_request(username_bytes, client_socket, server_addr):
    """
    executes client logic to process a read request

    @param username_bytes -> bytes                             --> the client's username
    @param client_socket  -> socket.socket                     --> the client socket
    @param server_addr    -> from socket.socket.getaddrinfo()  --> the server's address
    @returns              -> None
    """
    # send read request to server ----------------------------------------------------
    message_request = construct_message_request(0xAE73, 0x01, len(username_bytes), 0, 0, bytearray(username_bytes))

    client_socket.connect(server_addr[0][-1])
    client_socket.sendall(message_request)
    print("sending message request to server")
    
    # receive response header ---------------------------------------------------------
    response_header = client_socket.recv(common.RESPONSE_FIXED_HDR_SIZE)
    deconstructed_response_header = deconstruct_message_response_header(response_header)

    verification_flag = deconstructed_response_header[0]

    if verification_flag is False:
        print("[ERROR] server response could not be verified... skipping")
        return
    
    # deconstruct response header ------------------------------------------------------
    num_items = deconstructed_response_header[1][2]
    messages = list()

    for _ in range(num_items):
        # receive and deconstruct message header ---------------------------------------
        item_header = client_socket.recv(common.RESPONSE_MESSAGE_HDR_SIZE)
        sender_len = common.extract_data_from_byte_arr(item_header, 0, 1)
        message_len = common.extract_data_from_byte_arr(item_header, 1, 3)

        # verify message header
        if sender_len < 1 or message_len < 1 :
            print("[ERROR] server response could not be verified... skipping")
            return

        # receive and deconstruct message body ------------------------------------------
        item_body = client_socket.recv(sender_len + message_len)
        sender = item_body[0:sender_len].decode("UTF-8")
        content = item_body[sender_len:].decode("UTF-8")

        messages.append((sender, content))

    # display messages only after we know the response is valid -------------------------
    print(f"\nreceived {num_items} message(s)")
    for sender, content in messages : print(f"message from {sender} : \"{content}\"")

    # log more messages ------------------------------------------------------------------
    if deconstructed_response_header[1][3] == 1:
        print(f"\nmore messages in server storage")
    else:
        print(f"\nno more messages in server storage")


def main():

    # system argument extraction ---------------------------------------------------
    if len(sys.argv) != SYSTEM_ARGUMENTS:
        print("Incorrect usage, expected: python client.py <address> <port> <name> <type>")
        sys.exit()

    server_addr = sys.argv[1]
    server_port = sys.argv[2]
    client_name = sys.argv[3]
    client_type = sys.argv[4]

    client_socket = None
    client_name_bytes = client_name.encode("UTF-8")

    # system argument verification ---------------------------------------------------
    if server_port.isnumeric() is False:
        print("Incorrect usage, port must be numeric")
        sys.exit()

    server_port = int(server_port)
    
    if not 1024 <= server_port <= 64000:
        print("Incorrect usage, port must be in the bounds of : 1024 <= port <= 64000")
        sys.exit()

    if len(client_name) < 1:
        print("client name must be at least one character in length") 
        sys.exit()
    
    if len(client_name_bytes) > 255:
        print("client name must be encodable within 255 bytes")
        sys.exit()
    
    if client_type not in ["read", "create"]:
        print("Incorrect usage, client type must be either 'read' or 'create'")
        sys.exit()
        
    try:
        # client initialization -------------------------------------------------------
        server_addr = socket.getaddrinfo(server_addr, server_port)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(1.0)

        try:
            # process request type --------------------------------------------------------
            if client_type == "read":
                process_read_request(client_name_bytes, client_socket, server_addr)
            
            if client_type == "create":
                process_create_request(client_name_bytes, client_socket, server_addr)
        except TimeoutError:
            print(f"Error: timed out. no response within 1.0seconds.")
            if client_socket is not None:
                print("closing client socket")
                client_socket.close()
            sys.exit()

    # error handling and socket closure -----------------------------------------------
    except OSError as error:
        print(f"{error}")
    finally:
        if client_socket is not None:
            print("closing client socket")
            client_socket.close()
    
if __name__ == "__main__":
    main()