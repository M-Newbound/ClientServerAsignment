"""
author: Martin Newbound (37202364)
23/08/2023

"""


import sys
import socket
import common

SYSTEM_ARGUMENTS = 2
MESSAGE_RESPONSE_MAX = 255

log_message = lambda title, message, newline=False : print(f"\n[{title}] {message}") if newline else print(f"[{title}] {message}")
server_storage = dict()

class ServerInitializationError(Exception) :   pass


def construct_message_response(magic_number, response_id, num_items, more_msgs, payload):
    """
    will construct a byte array which follows the message response format.

    @param magic_number ->  int                     --> the magic number header field
    @param response_id  ->  int                     --> the response id header field
    @param num_items    ->  int                     --> the number of items in the response
    @param more_msgs    ->  int                     --> 0 for no more items, 1 for more items
    @param payload      ->  list[tuple(str, str)]   --> the items in the response, note: len(payload) should == num_items
    
    @returns             -> bytearray               --> the fully constructed message response
    """
    
    # header construction -----------------------------------------------------------------
    response = bytearray(common.RESPONSE_FIXED_HDR_SIZE)
    
    common.load_data_into_byte_arr(response, magic_number, 0, 2, "magic-number")
    common.load_data_into_byte_arr(response, response_id,  2, 3, "response-id")
    common.load_data_into_byte_arr(response, num_items,    3, 4, "num-items")
    common.load_data_into_byte_arr(response, more_msgs,    4, 5, "more-msgs")

    # body construction ---------------------------------------------------------------------
    for sender, message in payload:
        sender_bytes  = sender.encode("UTF-8")
        message_bytes = message.encode("UTF-8")

        sender_len  = len(sender_bytes)
        message_len = len(message_bytes)

        payload_sub_hdr = bytearray(1 + 2)
        common.load_data_into_byte_arr(payload_sub_hdr, sender_len,  0, 1)
        common.load_data_into_byte_arr(payload_sub_hdr, message_len, 1, 3)

        response.extend(payload_sub_hdr)
        response.extend(sender_bytes)
        response.extend(message_bytes)
    
    return response


def deconstruct_message_request_header(message):
    """
    deconstruct a message request header bytearray

    @param message ->  bytearray                           --> the message request header to deconstruct
    @returns       ->  (bool, (int, int, int, int, int))   --> the header as, (verification_flag, (magic_num, id, name_len, receiver_len, message_len))

    note: verification flag is true if, and only if, the request header follows expected formatting
    """
    
    # setup & primary verification checks -----------------------------------------------------
    magic_number, msg_id, name_length, receiver_length, message_length = (0,0,0,0,0)
    package = lambda success : (success, (magic_number, msg_id, name_length, receiver_length, message_length))

    if message is None : return package(False)
    if len(message) != common.REQUEST_FIXED_HDR_SIZE  : return package(False)
    
    # data extraction -------------------------------------------------------------------------
    magic_number    = common.extract_data_from_byte_arr(message, 0, 2, "magic-number")
    msg_id          = common.extract_data_from_byte_arr(message, 2, 3, "id")
    name_length     = common.extract_data_from_byte_arr(message, 3, 4, "name-len")
    receiver_length = common.extract_data_from_byte_arr(message, 4, 5, "receiver-len")
    message_length  = common.extract_data_from_byte_arr(message, 5, 7, "message-len")

    # secondary verification checks -----------------------------------------------------------
    if magic_number != common.MAGIC_NUMBER_VALUE : return package(False)

    if msg_id not in (1, 2) : return package(False)
    if name_length < 1      : return package(False)

    if msg_id == 1 and receiver_length != 0 : return package(False)
    if msg_id == 1 and message_length  != 0 : return package(False)
    
    if msg_id == 2 and receiver_length < 1  : return package(False)
    if msg_id == 2 and message_length  < 1  : return package(False)

    return package(True)


def process_read_request(connection, deconstructed_header):    
    """ 
    executes server logic for processing a read type request

    @param connection            ->  socket.socket                                 --> the connection socket
    @param deconstructed_header  ->  tuple(bool, tuple(int, int, int, int, int))   --> a deconstructed header from a message request
    @returns                     ->  None
    """
    
    # receiving request payload -------------------------------------------------------------
    sender_name_length = deconstructed_header[1][2]
    request_payload_length =  sender_name_length

    request_payload = connection.recv(request_payload_length)

    if len(request_payload) != request_payload_length:
        log_message("Warning", "Message Request failed verification, discarding...")
        return

    sender_name = request_payload[0:sender_name_length].decode("UTF-8")
    
    # creating response payload -------------------------------------------------------------
    response_payload = list()

    if sender_name in server_storage:
        messages = server_storage[sender_name]

        if len(messages) <= MESSAGE_RESPONSE_MAX:
            response_payload = messages[:]
            messages.clear()
        else:
            response_payload = messages[:MESSAGE_RESPONSE_MAX]
            del messages[:MESSAGE_RESPONSE_MAX]
    
    # logging to console ----------------------------------------------------------------------
    num_msgs_after = len(server_storage.get(sender_name, []))
    num_msgs_before = num_msgs_after + len(response_payload)
   
    more_msgs = 1 if num_msgs_after > 0 else 0

    log_message("INFO", f"user {sender_name} has been sent {len(response_payload)} out of {num_msgs_before} messages from their storage")

    # construct & send response -----------------------------------------------------------------
    response = construct_message_response(0xAE73, 3, len(response_payload), more_msgs, response_payload)
    connection.sendall(response)


def process_create_request(connection, deconstructed_header):
    """ 
    executes server logic for processing a create type request

    @param connection            ->  socket.socket                                 --> the connection socket
    @param deconstructed_header  ->  tuple(bool, tuple(int, int, int, int, int))   --> a deconstructed header from a message request
    @returns                     ->  None
    """
    
    # receiving payload ------------------------------------------------------------------------
    message_length       = deconstructed_header[1][4]
    receiver_name_length = deconstructed_header[1][3]
    sender_name_length   = deconstructed_header[1][2]
    payload_length       = sender_name_length + receiver_name_length + message_length

    payload = connection.recv(payload_length)
    if len(payload) != payload_length:
        log_message("Warning", "Message Request failed verification, discarding...")
        return

    # deconstructing payload ----------------------------------------------------------------------
    sender_name     = payload[0 : sender_name_length].decode("UTF-8")
    receiver_name   = payload[sender_name_length : sender_name_length + receiver_name_length].decode("UTF-8")
    message         = payload[sender_name_length + receiver_name_length : ].decode("UTF-8")

    # loading data into storage --------------------------------------------------------------------
    if receiver_name in server_storage : server_storage[receiver_name].append((sender_name, message))
    else : server_storage[receiver_name] = [(sender_name, message)] 

    log_message("Info", f"user {sender_name} sent 1 message to {receiver_name} : {receiver_name} now has {len(server_storage[receiver_name])} unread messages")


def process_connection(connection):
    """ 
    executes server logic for processing a read type request

    @param connection            ->  socket.socket  --> the connection socket
    @returns                     ->  None
    """
    # receiving header --------------------------------------------------------------
    request_header       = connection.recv(common.REQUEST_FIXED_HDR_SIZE)
    deconstructed_header = deconstruct_message_request_header(request_header)
    verification_flag    = deconstructed_header[0]

    if verification_flag is False:
        log_message("Warning", "Message Request failed verification, discarding...")
        return

    # acting on request type -----------------------------------------------------------
    message_id        = deconstructed_header[1][1]
    is_read_message   = message_id == 1
    is_create_message = message_id == 2
    
    if is_read_message   : process_read_request(connection, deconstructed_header)
    if is_create_message : process_create_request(connection, deconstructed_header)


def shutdown_server(server_socket):
    """
    called when halting the server. Causes program to exit.

    @param server_socket -> socket.socket | None  --> the potentially open server socket 
    @returns             -> None
    """
    if server_socket is not None: 
        log_message("SERVER", "closing server socket", True)
        server_socket.close()
    
    sys.exit()


def fetch_port_number():
    """
    called to fetch the port number from system arguments.

    @returns -> int  --> the port number
    """
    if len(sys.argv) != SYSTEM_ARGUMENTS : raise ServerInitializationError("incorrect usage, expected: python server.py <port>")

    port_argument = sys.argv[1]
    if not port_argument.isnumeric()     : raise ServerInitializationError("port must be a numeric type")

    port_number = int(port_argument)
    if not 1024 <= port_number <= 64000  : raise ServerInitializationError(f"port as {port_number} is out of bounds, 1024<=port<=64000")

    return port_number


def main():
    
    server_port = None
    server_socket = None
    
    try:
        # initializing server ---------------------------------------------------- 
        server_port = fetch_port_number()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.bind(("0.0.0.0", server_port))
        server_socket.listen()

        # server runtime loop ----------------------------------------------------
        while True:
            connection, address = server_socket.accept()
            connection.settimeout(1.0)

            log_message("INFO", f"server accepted connection with {address[0]} through port {address[1]}", True)
            
            try:
                process_connection(connection)

            # connection troubleshooting & connection closure ------------------------
            except TimeoutError:
                log_message("Client Timeout", "connection timed out, skipping....")

            finally:
                if connection:
                    connection.close()
                    log_message("INFO", f"server closed connection with {address[0]}")
    
    # trouble shooting & server shutdown ------------------------------------------
    except OSError as error: 
        log_message("Server Error", f"{error}")
   
    except KeyboardInterrupt:
        log_message("User Action", "key interrupt detected")

    except UnicodeDecodeError:
        log_message("Server Error", "issue decoding message")

    except ServerInitializationError as error:
        log_message("Initialization Error", f"{error}", True)
   
    finally:
        shutdown_server(server_socket)

if __name__ == '__main__':
    main()
