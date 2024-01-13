from construct import Struct, Bytes, Int32ul, Int8ul, CString, Int16ul, Byte
import serial
import struct
import time
import os

# Define the response structure using construct
response_struct = Struct(
    "delimiter" / Bytes(2),
    "command" / Byte,
    "packet_number" / Byte,
    "response" / Byte,
    "error_code" / Byte,
)

# Protocol Constants
PROTOCOL_DELIMITER_BYTE_1 = 0xAA
PROTOCOL_DELIMITER_BYTE_2 = 0x55
PROTOCOL_ESC_BYTE = 0x5E
PROTOCOL_END_BYTE = 0x5F

# FTP Commands
CMD_FILE_INFO = 1
CMD_DATA_PACKET = 2
CMD_END_OF_FILE = 3
CMD_FILE_TRANSFER_ABORT = 4
CMD_JUMP_TO_APPLICATION = 5

# Define the data packet structure using construct
data_packet_struct = Struct(
    "header" / Struct(
        "delimiter" / Bytes(2),
        "command" / Int8ul,
        "command_length" / Int16ul,
    ),
    "checksum" / Int32ul,
    "packet_number" / Int16ul,
    "data_size" / Int16ul,
    "data" / Bytes(lambda ctx: ctx.data_size),
)

# Define the main packet structure using construct
file_info_packet_struct = Struct(
    "header" / Struct(
        "delimiter" / Bytes(2),
        "command" / Int8ul,
        "command_length" / Int16ul,
    ),
    "checksum" / Int32ul,
    "file_size" / Int32ul,
    "file_name_length" / Int8ul,
    "file_name" / CString("utf-8"),
)

# Define the main packet structure using construct
cmd_packet_struct = Struct(
    "header" / Struct(
        "delimiter" / Bytes(2),
        "command" / Int8ul,
        "command_length" / Int16ul,
    )
)


# Serial Port Configuration
ser = serial.Serial('COM12', 115200)

# Function to calculate checksum
def calculate_checksum(packet):
    return sum(packet) & 0xFFFF

# Send a command packet
def send_command(command):
    packet = bytes([PROTOCOL_DELIMITER_BYTE_1, PROTOCOL_DELIMITER_BYTE_2, command])
    checksum = calculate_checksum(packet)
    packet += bytes(struct.pack('<H', checksum))
    packet += bytes([PROTOCOL_END_BYTE])
    ser.write(packet)

def send_file_info(file_info):
    """
    Sends file information packet to the serial port.

    Args:
        file_info (dict): Dictionary containing file information.
            - 'fileSize': Size of the file.
            - 'fileNameLength': Length of the file name.
            - 'fileName': Name of the file.

    Returns:
        None
    """
    # Initialize packet data
    packet_data = {
        "header": {
            "delimiter": 0x0000,  # Placeholder for the correct calculation
            "command": 0,  # Placeholder for the correct calculation
            "command_length": 0,  # Placeholder for the correct calculation
        },
        "checksum": 0,  # Placeholder for the correct calculation
        "file_size": file_info['fileSize'],
        "file_name_length": file_info['fileNameLength'],
        "file_name": file_info['fileName'],
    }

    # Calculate the checksum
    packet_data["checksum"] = calculate_checksum(file_info_packet_struct.build(packet_data))

    # Update header values
    packet_data["header"]["delimiter"] = bytes([PROTOCOL_DELIMITER_BYTE_1, PROTOCOL_DELIMITER_BYTE_2])
    packet_data["header"]["command"] = CMD_FILE_INFO

    # Calculate the length of the header
    header_struct = file_info_packet_struct.header
    packet_data["header"]["command_length"] = len(file_info_packet_struct.build(packet_data)) - header_struct.sizeof()

    # Build the final packet with strict byte order
    final_packet = file_info_packet_struct.build(packet_data)

    # Write the final packet to the serial port
    ser.write(final_packet)

def send_data_packet(packet_number, data):
    """
    Sends a data packet to the serial port.

    Args:
        packet_number (int): Packet number.
        data (bytes): Data to be sent.

    Returns:
        None
    """
    try:
        # Create the packet using construct
        packet_data = {
            "header": {
                "delimiter": 0x0000,  # Placeholder for the correct calculation
                "command": 0,  # Placeholder for the correct calculation
                "command_length": 0,  # Placeholder for the correct calculation
            },
            "checksum": 0,  # Placeholder for the correct calculation
            "packet_number": packet_number,
            "data_size": len(data),
            "data": data,
        }
        
        
        # Calculate the checksum
        packet_data["checksum"] = calculate_checksum(data_packet_struct.build(packet_data))

        # Update header values
        packet_data["header"]["delimiter"] = bytes([PROTOCOL_DELIMITER_BYTE_1, PROTOCOL_DELIMITER_BYTE_2])
        packet_data["header"]["command"] = CMD_DATA_PACKET

        # Calculate the length of the header
        header_struct = data_packet_struct.header
        packet_data["header"]["command_length"] = len(data_packet_struct.build(packet_data)) - header_struct.sizeof()

        # Build the final packet with strict byte order
        final_packet = data_packet_struct.build(packet_data)

        # Write the final packet to the serial port
        ser.write(final_packet)
    except Exception as e:
        print(f"Error sending data packet: {e}")
  
def send_jump_to_application():
    try:
        # Create the packet using construct
        packet_data = {
            "header": {
                "delimiter": 0x0000,  # Placeholder for the correct calculation
                "command": 0,  # Placeholder for the correct calculation
                "command_length": 0,  # Placeholder for the correct calculation
            }
        }
        
        # Update header values
        packet_data["header"]["delimiter"] = bytes([PROTOCOL_DELIMITER_BYTE_1, PROTOCOL_DELIMITER_BYTE_2])
        packet_data["header"]["command"] = CMD_JUMP_TO_APPLICATION

        # Build the final packet with strict byte order
        final_packet = cmd_packet_struct.build(packet_data)

        # Write the final packet to the serial port
        ser.write(final_packet)
    except Exception as e:
        print(f"Error sending data packet: {e}")
  
# Example usage
filename = 'GPIO_EXTI.bin'
file_info = {'fileSize': os.path.getsize(filename), 'fileNameLength': len(filename), 'fileName': filename}

try:
    send_file_info(file_info)
    time.sleep(0.1)
    received_bytes = ser.read(6)
    
    # Parse the received bytes using the defined structure
    response_data = response_struct.parse(received_bytes)
    
    # Check the response values
    if response_data.delimiter == b'\xaa\x55' and response_data.response == 0xA5:
        print(f"Valid response. Response: {hex(response_data.response)}, Error Code: {hex(response_data.error_code)}")
        
        with open(filename, 'rb') as file:
            chunk_size = 512
            while True:
                data_chunk = file.read(chunk_size)
                print("data_chunk", data_chunk)
                if not data_chunk:
                    break  # Reached end of file
                send_data_packet(1, data_chunk)
                time.sleep(0.5)
                received_bytes = ser.read(6)
                # Parse the received bytes using the defined structure
                response_data = response_struct.parse(received_bytes)

                # Check the response values
                if response_data.delimiter == b'\xaa\x55' and response_data.response == 0xA5:
                    print(f"Valid response. Response: {hex(response_data.response)}, Error Code: {hex(response_data.error_code)}")
                else:
                    print("Invalid response.")
    else:
        print("Invalid response.")
    time.sleep(2)
    send_jump_to_application()
    # send_command(CMD_END_OF_FILE)
finally:
    ser.close()
