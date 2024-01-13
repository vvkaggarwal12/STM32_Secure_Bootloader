#include "main.h"
#include "ftp.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Enum for FTP commands
typedef enum {
	CMD_FILE_INFO = 1,
	CMD_DATA_PACKET = 2,
	CMD_END_OF_FILE = 3,
	CMD_FILE_TRANSFER_ABORT = 4,
	CMD_JUMP_TO_APPLICATION = 5,
} command_t;

// Protocol Constants
#define PROTOCOL_DELIMITER_BYTE_1 0xAA
#define PROTOCOL_DELIMITER_BYTE_2 0x55
#define PROTOCOL_ESC_BYTE 0x5E
#define PROTOCOL_END_BYTE 0x5F
#define APPLICATION_ADDRESS		ADDR_FLASH_SECTOR_1_BANK1

// Maximum data size per packet
#define MAX_DATA_SIZE 512
#define MAX_FILE_NAME_SIZE 64

// File information structure
typedef struct __attribute__((packed)) {
	uint32_t fileSize;
	uint8_t fileNameLength;
	int8_t fileName[MAX_FILE_NAME_SIZE]; /* This should be the last member of the protocol as this is not fixed in length */
} FileInfo_t;

// Data packet structure
typedef struct __attribute__((packed)) {
	uint16_t packetNumber;
	uint16_t dataSize;
	uint8_t data[MAX_DATA_SIZE]; /* This should be the last member of the protocol as this is not fixed in length */
} DataPacket_t;

// Protocol packet structure
typedef struct __attribute__((packed)) {
	uint32_t checksum; /* checksum should be the first member of this structure */
	FileInfo_t fileInfo;
} FileInfoProtocolPacket_t;

typedef struct __attribute__((packed)) {
	uint32_t checksum; /* checksum should be the first member of this structure */
	DataPacket_t dataPacket;
} DataProtocolPacket_t;

enum {
	RESPONSE_ACK = 0xA5,
	RESPONSE_NACK = 0x33
};

typedef struct __attribute__((packed)) {
	uint8_t delimiter[2];
	uint8_t command;
	uint8_t packetNumber;
	uint8_t response;
	uint8_t errorCode;
} response_t;

// Global variables
static DataProtocolPacket_t dataPacket_sg;
static FileInfoProtocolPacket_t fileInfo_sg;

enum {
	WAITING_FOR_DELIMITER_1 = 0,
	WAITING_FOR_DELIMITER_2 = 1,
	WAITING_FOR_COMMAND = 2,
	WAITING_FOR_COMMAND_LENGTH = 3,
	WAITING_FOR_FILE_INFO = 4,
	WAITING_FOR_DATA_PACKET = 5,
	WAITING_FOR_END_OF_FILE = 6
};

static uint8_t state_sg = WAITING_FOR_DELIMITER_1;

// Function to calculate checksum
uint16_t calculateChecksum(const uint8_t *packet, uint32_t packetSize) {
	uint16_t sum = 0;
	const uint8_t *bytes = (const uint8_t*) packet;

	// Exclude checksum field from calculation
	for (size_t i = 0; i < packetSize; ++i) {
		sum += bytes[i];
	}

	return sum;
}

uint8_t prepare_response(uint8_t command, uint8_t response)
{
	response_t res;

	memset(&res, 0x00, sizeof(res));
	res.delimiter[0] = PROTOCOL_DELIMITER_BYTE_1;
	res.delimiter[1] = PROTOCOL_DELIMITER_BYTE_2;
	res.command = command;
	res.response = response;

	COM_Transmit((uint8_t *)&res, sizeof(res), 2000);
	return 1;
}

// Define the application start address
#define APP_START_ADDRESS APPLICATION_ADDRESS  // Replace with the actual start address of your application

// Function to jump to the application
void jumpToApplication(unsigned int address) {
    // Disable interrupts
//    __disable_irq();

    // Configure the vector table (optional, depending on your system)
    SCB->VTOR = address;

    // Set the program counter (PC)
	asm("LDR SP,[R0]");
	asm("LDR PC, [R0,#4]");

    // This point should not be reached, but if it is, enable interrupts
//    __enable_irq();
}

void parse_data_received(uint8_t data) {
	const DataProtocolPacket_t *dataPacketPtr = &dataPacket_sg;
	const FileInfoProtocolPacket_t *fileInfoPtr = &fileInfo_sg;
	static uint16_t commandLen = 0;
	static uint16_t commandDataIndex = 0;
	static uint8_t command;
	static uint32_t current_flash_addr = APPLICATION_ADDRESS;
	uint16_t expectedChecksum = 0;

	switch (state_sg) {
	case WAITING_FOR_DELIMITER_1:
		if ((PROTOCOL_DELIMITER_BYTE_1 == data)) {
			state_sg = WAITING_FOR_DELIMITER_2;
		}
		break;
	case WAITING_FOR_DELIMITER_2:
		if ((PROTOCOL_DELIMITER_BYTE_2 == data)) {
			state_sg = WAITING_FOR_COMMAND;
		}
		break;
	case WAITING_FOR_COMMAND:
		command = data;
		state_sg = WAITING_FOR_COMMAND_LENGTH;
		break;
	case WAITING_FOR_COMMAND_LENGTH:
		// Calculate command_len directly
		commandLen |= data << (8 * commandDataIndex);
		commandDataIndex++;
		if (commandDataIndex == sizeof(commandLen))
		{
			switch (command) {
			case CMD_FILE_INFO:
				memset(&fileInfo_sg, 0x00, sizeof(fileInfo_sg));
				memset(&dataPacket_sg, 0x00, sizeof(dataPacket_sg));
				state_sg = WAITING_FOR_FILE_INFO;
				break;
			case CMD_DATA_PACKET:
				memset(&fileInfo_sg, 0x00, sizeof(fileInfo_sg));
				memset(&dataPacket_sg, 0x00, sizeof(dataPacket_sg));
				state_sg = WAITING_FOR_DATA_PACKET;
				break;
			case CMD_END_OF_FILE:
				state_sg = WAITING_FOR_END_OF_FILE;
				break;
			case CMD_FILE_TRANSFER_ABORT:
				memset(&fileInfo_sg, 0x00, sizeof(fileInfo_sg));
				memset(&dataPacket_sg, 0x00, sizeof(dataPacket_sg));
				state_sg = WAITING_FOR_DELIMITER_1;
				current_flash_addr = APPLICATION_ADDRESS;
				break;
			case CMD_JUMP_TO_APPLICATION:
	            state_sg = WAITING_FOR_DELIMITER_1;
	            jumpToApplication(APPLICATION_ADDRESS);
//	            launch_application(APPLICATION_ADDRESS, (uint32_t)jump_to_function);
	            break;
			default:
				memset(&fileInfo_sg, 0x00, sizeof(fileInfo_sg));
				memset(&dataPacket_sg, 0x00, sizeof(dataPacket_sg));
				state_sg = WAITING_FOR_DELIMITER_1;
				prepare_response(command, RESPONSE_NACK);
				break;
			}
			// Reset command-related variables
			commandDataIndex = 0;
		}
		break;
	case WAITING_FOR_FILE_INFO:
		if (commandDataIndex < commandLen) {
			((uint8_t*) fileInfoPtr)[commandDataIndex++] = data;
		}
		if (commandDataIndex >= commandLen) {
			commandDataIndex = 0;
			expectedChecksum = calculateChecksum(
					(const uint8_t*) &fileInfo_sg.fileInfo,
					sizeof(fileInfo_sg.fileInfo));
			if ((fileInfo_sg.checksum != expectedChecksum)
					|| (fileInfo_sg.fileInfo.fileNameLength
							!= strlen((const char *)fileInfo_sg.fileInfo.fileName))) {
				memset(&fileInfo_sg, 0x00, sizeof(fileInfo_sg));
				prepare_response(command, RESPONSE_NACK);
			} else {
				prepare_response(command, RESPONSE_ACK);
//				current_flash_addr = APPLICATION_ADDRESS;
			}
			command = 0;
			commandLen = 0;
			state_sg = WAITING_FOR_DELIMITER_1;
		}
		break;
	case WAITING_FOR_DATA_PACKET:
		if (commandDataIndex < commandLen) {
			((uint8_t*) dataPacketPtr)[commandDataIndex++] = data;
		}
		if (commandDataIndex >= commandLen) {
			commandDataIndex = 0;
			expectedChecksum = calculateChecksum(
					(const uint8_t*) &dataPacket_sg.dataPacket,
					sizeof(dataPacket_sg.dataPacket));
			if ((dataPacket_sg.checksum != expectedChecksum)) {
				memset(&fileInfo_sg, 0x00, sizeof(fileInfo_sg));
				prepare_response(command, RESPONSE_NACK);
			} else {
				if (0 == (current_flash_addr % FLASH_SECTOR_SIZE)) {
					if (HAL_OK == erase_flash(current_flash_addr, ((current_flash_addr + FLASH_SECTOR_SIZE) - 1))) {
						program_flash(current_flash_addr, dataPacket_sg.dataPacket.data, dataPacket_sg.dataPacket.dataSize);
						prepare_response(command, RESPONSE_ACK);
						current_flash_addr += dataPacket_sg.dataPacket.dataSize;
					} else {
						prepare_response(command, RESPONSE_NACK);
					}
				} else {
					program_flash(current_flash_addr, dataPacket_sg.dataPacket.data, dataPacket_sg.dataPacket.dataSize);
					prepare_response(command, RESPONSE_ACK);
					current_flash_addr += dataPacket_sg.dataPacket.dataSize;
				}
			}
			command = 0;
			commandLen = 0;
			state_sg = WAITING_FOR_DELIMITER_1;
		}
		break;
	case WAITING_FOR_END_OF_FILE:
		state_sg = WAITING_FOR_DELIMITER_1;
		current_flash_addr = APPLICATION_ADDRESS;
		break;
	default:
		state_sg = WAITING_FOR_DELIMITER_1;
		break;
	}
}

enum {
	LOG_ERROR = 0, LOG_INFO, LOG_DEBUG, LOG_VERBOSE
};

static const int8_t *logLevelStrings[] = {
		(int8_t*) "ERROR",
		(int8_t*) "INFO",
		(int8_t*) "DEBUG",
		(int8_t*) "VERBOSE"
};

#define LOG_PRINTF(level, filename, line, fmt, ...)         printf("[%s:%d] [%s] " fmt "\n", filename, line, logLevelStrings[level], ##__VA_ARGS__)
