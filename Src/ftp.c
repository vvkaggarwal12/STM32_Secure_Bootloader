#include "main.h"
#include "ftp.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

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

#define FIRMWARE_SIZE 512
uint8_t firmware1[FIRMWARE_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
	0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
	0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
	0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
	0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
	0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
	0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
	0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
	0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
	0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
	0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
	0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
	0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
	0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
	0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
	0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
	0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
	0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
	0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00
};

const uint8_t *publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoTqUl+wfC9RR3T8dGCVj\nhZ9b0+oKpg4aagYcTtKmNOjX/595nXfWZjLIb4aIUeYzB2YWgVdu0OAwpW/o1Gw7\nWRl3DyKLvALXrNZKEgqc9PwmO3HE7pN0Gcnr5kfHsfNmZ/vkt4lkcxnqXl548xS0\nZPp4brlTQ6sKfMf3Kb/xvLiLZindYjDQuV1s3792Z9s2v6Qli6SPfBYcQ262NZL1\nFcTy/FrF12CKB84l8Qmx2RxELHdTpQ0V1Fx4ZvamJtVr7KCPgd/ULJLlaSoequn+\nP1M8GQi4Cqggy48BhiJ30MTS6ZNalmjkT55zHH1pIOlIPeP9pjPvduyrv5jQdTYD\nwwIDAQAB\n-----END PUBLIC KEY-----\n";

const uint8_t *privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAoTqUl+wfC9RR3T8dGCVjhZ9b0+oKpg4aagYcTtKmNOjX/595\nnXfWZjLIb4aIUeYzB2YWgVdu0OAwpW/o1Gw7WRl3DyKLvALXrNZKEgqc9PwmO3HE\n7pN0Gcnr5kfHsfNmZ/vkt4lkcxnqXl548xS0ZPp4brlTQ6sKfMf3Kb/xvLiLZind\nYjDQuV1s3792Z9s2v6Qli6SPfBYcQ262NZL1FcTy/FrF12CKB84l8Qmx2RxELHdT\npQ0V1Fx4ZvamJtVr7KCPgd/ULJLlaSoequn+P1M8GQi4Cqggy48BhiJ30MTS6ZNa\nlmjkT55zHH1pIOlIPeP9pjPvduyrv5jQdTYDwwIDAQABAoIBACS5gz9XuXqoUj1j\nMu1dFt5I/lG27dYFQF8GJUyPDuzeXNUNLlaABYYh6yX8LvD4zobQ6i9sCwHpDyuf\n4hkAzkPtWQFJjSq2OwpThWu2nynuhYbk00bEr51wMRuzHfmax6jH58Emuoq9THVS\nb5pvDOgzZVtTO3QecbUal2IbJqUlxypklyZAheH7Wk2RK+wYRBV0XKjlTL2BwbWU\nk4wPTjf+RplTCP/7DChVVkpvE4qPC2iXJEhJygltaQbVbQMiriyIGoG02CM1WndL\n2qcFTCy6ZT/qgxfkMpx/0suBcWgeSq36FszOWYsDiblpZCu3Y0IVpjO/OYuTw39k\n2HVWGQECgYEA3pWcdU+wlo2JmkDk+q1F6JiePwgEBe+hL+72DtpvApGwRCiXnWn4\n8vHQ4aFFjmLKTuDrCSmu6v2YXgScVr7rObcpMyOBuG4uWNFXA1JYYuPnhv81NeC5\n0HNGYBmVM9mPMv4ANSQbyQP7YKCPYcFOSYup6Ho9jfipDV2K6H4PfYkCgYEAuW7x\nzfUCoDLwsl1adTDFUcIt7Jj+1CIFiW0O3AbbDzN422vhTN5hnrXt7MmAIEdbL1Vh\n0KpSDfk17iK46BdAVIU0Sl2OOyjljKaIcOeGBye5UvgUwppNnohCVPN51lKVnGrO\nmwnyc3yHAPnRiMuDsJvZW4b2+d2FfJRl2T+cz+sCgYEArT/gh0Me3SCP4Vvvntqt\n1mysh70yfHhXixrBtS/6RhKmE3dRA7qPhnIINwczP6/PbnQNHZWvS8NWDKAkHDUA\nnGzfialyd95y/rj6tGAs4dQoy1/rx+MCXqjLN1PSWYhWuMcR3EsdwWnzCPQQhnNS\n/1XRS12SeeX5l6iezXYJkpkCgYBpx2EGlPKHgieOB/TXDxgweG2MHwaW6kVwTJcC\naqLBvCIAQT0HhX/4cl2kCpodT7czfChNSSt/rx7VllcWhlT7IfVfSpkdJEo1/rWs\nelYZdM6iBsSI8k6+1YnJPg7NdNTFoqPzCyyUNoAozVl7CGU59N17+bSfen9wPpMO\n59vDOwKBgFrNglGipu1hKdgO1dt/I1e2ucKggIBIA7uprrWsWyrPmvLg8LaOBjWs\npTBnAKF+coW3uN5wlkVfieLueuavJ+fKzMXQwgAUywEXzl2JCjOomIipzijsMrHv\nmEJ25lJw/EVKycbZL3XOmOKKZVWMAIWURxoFy885HdmmmGcoEfNn\n-----END RSA PRIVATE KEY-----\n";

uint8_t digest[] = { 0x28, 0x39, 0x8f, 0xf0, 0x46, 0xbc, 0x53, 0x5a, 0x23, 0x7d, 0xe1, 0x95, 0x15, 0x52, 0x97, 0xbe, 0xfb, 0x04, 0x82, 0x72, 0x9a, 0xe8, 0x10, 0xc6, 0x23, 0x85,
		0x64, 0xf4, 0x40, 0xbe, 0x76, 0xa1 };

uint8_t signedSignature[] = {0x03, 0x28, 0x1e, 0x86, 0x05, 0x0f, 0x0a, 0x01, 0xc5, 0x33, 0x0d, 0xf4, 0x8f, 0xa9, 0x0c, 0x3d, 0x41, 0x20, 0xf2, 0x82, 0x7f, 0x60, 0x06, 0xb5, 0x58, 0x9b,
		0xc7, 0x2f, 0xd1, 0x2a, 0x79, 0xcc, 0x5f, 0xba, 0x19, 0x53, 0xb7, 0x9b, 0xe4, 0xd7, 0x44, 0xb8, 0x89, 0x0f, 0x97, 0x27, 0x41, 0x46, 0xb4, 0x9f, 0x17, 0x9e, 0xe2, 0x10, 0x2a, 0xa1, 0x2e, 0xb4, 0x55, 0xa0, 0x9c, 0xa1, 0xe9, 0xc4, 0x99, 0x91, 0xbc, 0xfb, 0x6e, 0xc1, 0x0a, 0x4f, 0x22, 0xb2, 0x13, 0x01, 0xbf, 0x0a, 0xf4, 0x3e, 0x19, 0x0e, 0x17, 0x79, 0x2e, 0x09, 0x1c,
		0x28, 0xba, 0x3f, 0x5e, 0x39, 0x1d, 0x9d, 0x12, 0x8f, 0x50, 0x7d, 0xc4, 0xf8, 0xaf, 0x0d, 0x57, 0x12, 0x5d, 0xb1, 0x8e, 0xb4, 0xdc, 0x0a, 0x66, 0x68, 0x91, 0x52, 0x14, 0x96, 0x56, 0xeb, 0x51, 0x96, 0x42, 0x8b, 0xe4, 0x70, 0xc2, 0x2d, 0x84, 0x80, 0xc7, 0x74, 0x3a, 0xac, 0x5b, 0x7a, 0x0f, 0xf5, 0xc7, 0xa4, 0x34, 0x80, 0xfa, 0x8d, 0x3c, 0x32, 0x7d, 0xf3, 0xca, 0x79,
		0x63, 0x53, 0x82, 0x4f, 0x2b, 0xa8, 0xe9, 0x63, 0xb2, 0x55, 0xed, 0xaa, 0xa9, 0xd5, 0xc7, 0x1e, 0x6d, 0xb1, 0x70, 0x09, 0x25, 0xba, 0xaf, 0x89, 0xe6, 0xfb, 0xd7, 0x13, 0xae, 0x9e, 0xd0, 0x15, 0x05, 0xfd, 0xa8, 0x73, 0x03, 0x32, 0x7e, 0x96, 0xd5, 0x3a, 0x16, 0x92, 0x8d, 0x49, 0xfc, 0x82, 0x4f, 0x48, 0xf3, 0x78, 0x36, 0x55, 0x96, 0xd5, 0xbe, 0x3f, 0x53, 0xdd, 0x2d,
		0x3c, 0x62, 0x87, 0x24, 0x71, 0xd7, 0xad, 0xef, 0x02, 0x42, 0x5c, 0x11, 0x8f, 0x57, 0xe4, 0x4e, 0x3d, 0x09, 0x5c, 0xaf, 0xb9, 0x71, 0x27, 0x14, 0x92, 0x55, 0xa9, 0x12, 0x63, 0x49, 0x17, 0x6c, 0x38, 0x36, 0x9a, 0x8a, 0x16, 0x86, 0xad, 0x1c, 0x55, 0xcd, 0xea, 0xe2, 0x7d, 0x65, 0xe6 };
//uint8_t signedSignature[512];

int custom_entropy_source(void *data, unsigned char *output, size_t len, size_t *olen) {
    // Fill output with some pseudo-random data (NOT SECURE, only for testing)
    for (size_t i = 0; i < len; i++) {
        output[i] = (unsigned char)rand();
    }
    *olen = len;
    return 0;
}


int sign_firmware(const uint8_t *firmware, uint32_t size, uint8_t *signedSignature, size_t *sigLen) {
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret;

    // Initialize contexts
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Parse the private key
    ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)privateKey, strlen((const char *)privateKey) + 1, NULL, 0);
    if (ret != 0) {
        char error_buf[100];
//        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
//        LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Failed to parse private key: %s (-0x%04x)", error_buf, -ret);
        goto cleanup;
    }

    // Add this check
    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
        LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Parsed key is not RSA");
        goto cleanup;
    }

    // Seed the random number generator
    const char *pers = "sign_firmware";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, custom_entropy_source, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Failed to seed RNG: -0x%04x", -ret);
        goto cleanup;
    }

    // Compute the SHA-256 hash of the firmware
    uint8_t hash[32];
    ret = mbedtls_sha256_ret(firmware, size, hash, 0);
    if (ret != 0) {
        LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Failed to compute hash: -0x%04x", -ret);
        goto cleanup;
    }

    // Sign the hash
    LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Attempting to sign hash...");
    LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Hash size: %d", sizeof(hash));
    LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Signature buffer size: %d", *sigLen);

    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signedSignature, sigLen, 
                          mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0) {
//        char error_buf[100];
//        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
//        LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Failed to sign hash: %s (-0x%04x)", error_buf, -ret);
        LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Key type: %s", mbedtls_pk_get_name(&pk));
        LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Key size: %d bits", (int)mbedtls_pk_get_bitlen(&pk));
        goto cleanup;
    }

    LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Signature created successfully. Signature length: %d", *sigLen);
    LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Firmware signed successfully");
    ret = 0;

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}


int verify_firmware(const uint8_t *firmware, uint32_t size) {
	// Extract public key from the certificate
	uint32_t signatureLen = 256;
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	int ret = mbedtls_pk_parse_public_key(&pk, publicKey, (strlen((const char *)publicKey) + 1));
	if (ret != 0) {
		mbedtls_pk_free(&pk);
		LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Failed to parse public key");
		return -1;
	}

	// Compute the SHA-256 hash of the firmware
	uint8_t computedHash[32];

	mbedtls_sha256_context sha256_ctx;

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts_ret(&sha256_ctx, 0);
	mbedtls_sha256_update_ret(&sha256_ctx, firmware1, FIRMWARE_SIZE);
	mbedtls_sha256_finish_ret(&sha256_ctx, computedHash);
	mbedtls_sha256_free(&sha256_ctx);

	if (memcmp(computedHash, digest, sizeof(computedHash)) != 0) {
		LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Hash mismatch");
		return -1;
	}

//	sign_firmware(firmware1, sizeof(firmware1), signedSignature, &signatureLen);

	// verify the signature
	ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, computedHash, sizeof(computedHash), signedSignature, signatureLen);

	mbedtls_pk_free(&pk);
	if (ret != 0) {
		LOG_PRINTF(LOG_ERROR, __FILE__, __LINE__, "Failed to verify signature");
		return -1;
	}

	LOG_PRINTF(LOG_INFO, __FILE__, __LINE__, "Firmware verification successful");
	return 0;
}




