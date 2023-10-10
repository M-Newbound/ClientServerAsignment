"""
author: Martin Newbound (37202364)
23/08/2023

"""



MAGIC_NUMBER_VALUE = 0xAE73

REQUEST_FIXED_HDR_SIZE = 7

RESPONSE_FIXED_HDR_SIZE = 5
RESPONSE_MESSAGE_HDR_SIZE = 3

is_enough_bytes = lambda data, num_bytes : data <= (2**(num_bytes*8)) - 1



def bounds_check_byte_arr(arr, start_index, end_index, debug_name):
    """
    helper function to verify attribute values

    @param arr         -> bytearray  --> the byte array to check against
    @param start_index -> int        --> the start index of a specific slice
    @param end_index   -> int        --> the end index of a specific slice
    @param debug_name  -> str        --> a string which helps identify debug messages
    returns            -> None       
    """
    error_title = f"<error:  {debug_name}> "

    if arr is None                                 : raise AttributeError(error_title + f"undefined bytearray")
    if end_index <= start_index or start_index < 0 : raise AttributeError(error_title + f"start and end indices must follow 0 <= start < end ")
    if len(arr) < end_index                        : raise AttributeError(error_title + "end_index exceeds bytearray length") 


def extract_data_from_byte_arr(arr, start_index, end_index, debug_name = ""):
    """
    obtain the unsigned integer which represents a certain bytearray slice

    @param arr         -> bytearray  --> the byte array to check against
    @param start_index -> int        --> the start index of a specific slice
    @param end_index   -> int        --> the end index of a specific slice
    @param debug_name  -> str        --> a string which helps identify debug messages
    @returns           -> int        --> the unsigned integer

    """
    bounds_check_byte_arr(arr, start_index, end_index, debug_name)
    return int.from_bytes(arr[start_index:end_index], 'big', signed = False)


def load_data_into_byte_arr(arr, data, start_index, end_index, debug_name = ""):
    """
    set a certain slice of a bytearray to represent a specific unsigned integer

    @param arr         -> bytearray  --> the byte array to check against
    @param start_index -> int        --> the start index of a specific slice
    @param end_index   -> int        --> the end index of a specific slice
    @param debug_name  -> str        --> a string which helps identify debug messages
    @returns           -> None

    """

    bounds_check_byte_arr(arr, start_index, end_index, debug_name)
    total_bytes = end_index - start_index

    if data < 0 or not is_enough_bytes(data, total_bytes):
        raise AttributeError(f"<error: loading {debug_name} data into bytearray> data value {data} exceeds data limit and can not be encoded within {total_bytes} bytes.")

    data_bytes = data.to_bytes(length=total_bytes, byteorder='big', signed=False)
  
    for j in range(start_index, end_index):
        arr[j] = data_bytes[j-start_index]


