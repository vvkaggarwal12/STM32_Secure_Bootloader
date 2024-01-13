/**
 ******************************************************************************
 * @file    FLASH/FLASH_EraseProgram/Src/flash.c
 * @author  MCD Application Team
 * @brief   This example provides a description of how to erase and program the
 *          STM32H7xx FLASH.
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2017 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "string.h"

static uint32_t GetSector(uint32_t Address);
/** @addtogroup STM32H7xx_HAL_Examples
 * @{
 */
#define SINGLE_TRANSFER_N_BYTE	32
#define FLASH_USER_START_ADDR   ADDR_FLASH_SECTOR_1_BANK1      /* Start @ of user Flash area Bank1 */
#define FLASH_USER_END_ADDR     (ADDR_FLASH_SECTOR_7_BANK1 - 1)  /* End @ of user Flash area Bank1*/

/** @addtogroup FLASH_EraseProgram
 * @{
 */
/**
 * @brief  Erases a range of flash memory.
 * @note   This function assumes that the flash has been unlocked before calling.
 * @param  start_addr: The starting address of the flash range to be erased.
 * @param  end_addr: The ending address of the flash range to be erased.
 * @retval HAL_StatusTypeDef: HAL_OK if successful, HAL_ERROR if an error occurs.
 */
HAL_StatusTypeDef erase_flash(uint32_t start_addr, uint32_t end_addr) {
	/* Variable to store the status */
	HAL_StatusTypeDef erase_status = HAL_OK;

	do {
		/* Check if start_addr and end_addr are within the valid flash range */
		if ((start_addr < FLASH_USER_START_ADDR)
				|| (end_addr > FLASH_USER_END_ADDR)
				|| (start_addr > end_addr)) {
			/* Invalid flash range, update the status */
			erase_status = HAL_ERROR;
			break;  // Exit the loop if the range is invalid
		}

		/* Unlock the Flash to enable the flash control register access */
		HAL_FLASH_Unlock();

		/* Erase the user Flash area (defined by start_addr and end_addr) */
		/* Get the 1st sector to erase */
		uint32_t first_sector = GetSector(start_addr);

		/* Get the number of sectors to erase from the 1st sector */
		uint32_t nb_of_sectors = GetSector(end_addr) - first_sector + 1;

		/* Fill EraseInit structure */
		FLASH_EraseInitTypeDef EraseInitStruct = { 0 };
		EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
		EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
		EraseInitStruct.Banks = FLASH_BANK_1;
		EraseInitStruct.Sector = first_sector;
		EraseInitStruct.NbSectors = nb_of_sectors;

		/* Perform Flash memory erasure */
		erase_status = HAL_FLASHEx_Erase(&EraseInitStruct, NULL);

		/* Lock the Flash after the operation */
		HAL_FLASH_Lock();

	} while (0);  // The loop will run only once

	return erase_status;
}

/**
  * @brief  Programs data into the internal flash memory.
  * @note   This function assumes that the flash has been unlocked before calling.
  * @param  dest_addr: The destination address in the flash memory.
  * @param  data: Pointer to the data to be programmed.
  * @param  size: Size of the data to be programmed in bytes.
  * @retval HAL_StatusTypeDef: HAL_OK if successful, HAL_ERROR if an error occurs.
  */
HAL_StatusTypeDef program_flash(uint32_t dest_addr, uint8_t *data, uint32_t size) {
  /* Variable to store the status */
  HAL_StatusTypeDef program_status;
  uint8_t data_word[SINGLE_TRANSFER_N_BYTE];
  uint32_t bytes_to_copy;

  do {
    /* Check if dest_addr is within the valid flash range */
    if ((dest_addr < FLASH_USER_START_ADDR) || ((dest_addr + size - 1) > FLASH_USER_END_ADDR)) {
      /* Invalid flash range, update the status */
      program_status = HAL_ERROR;
      break;  // Exit the loop if the range is invalid
    }

    /* Unlock the Flash to enable the flash control register access */
    HAL_FLASH_Unlock();

    /* Program the user Flash area */
    for (uint32_t i = 0; i < size; i += SINGLE_TRANSFER_N_BYTE) {

      bytes_to_copy = (size - i) > SINGLE_TRANSFER_N_BYTE ? SINGLE_TRANSFER_N_BYTE : (size - i);
	  memset(data_word, 0x00, sizeof(data_word));
	  memcpy(data_word, &data[i], bytes_to_copy);

      /* Perform Flash memory programming */
      program_status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_FLASHWORD, dest_addr + i, (uint32_t)data_word);

      /* Check for programming errors */
      if (program_status != HAL_OK) {
        /* Lock the Flash in case of an error */
        HAL_FLASH_Lock();
        break;
      }
    }

    /* Lock the Flash after successful programming */
    HAL_FLASH_Lock();

  } while (0);  // The loop will run only once

  return program_status;
}

/**
  * @brief  Gets the sector of a given address
  * @param  Address Address of the FLASH Memory
  * @retval The sector of a given address
  */
static uint32_t GetSector(uint32_t Address)
{
  uint32_t sector = 0;

  if(((Address < ADDR_FLASH_SECTOR_1_BANK1) && (Address >= ADDR_FLASH_SECTOR_0_BANK1)) || \
     ((Address < ADDR_FLASH_SECTOR_1_BANK2) && (Address >= ADDR_FLASH_SECTOR_0_BANK2)))
  {
    sector = FLASH_SECTOR_0;
  }
  else if(((Address < ADDR_FLASH_SECTOR_2_BANK1) && (Address >= ADDR_FLASH_SECTOR_1_BANK1)) || \
          ((Address < ADDR_FLASH_SECTOR_2_BANK2) && (Address >= ADDR_FLASH_SECTOR_1_BANK2)))
  {
    sector = FLASH_SECTOR_1;
  }
  else if(((Address < ADDR_FLASH_SECTOR_3_BANK1) && (Address >= ADDR_FLASH_SECTOR_2_BANK1)) || \
          ((Address < ADDR_FLASH_SECTOR_3_BANK2) && (Address >= ADDR_FLASH_SECTOR_2_BANK2)))
  {
    sector = FLASH_SECTOR_2;
  }
  else if(((Address < ADDR_FLASH_SECTOR_4_BANK1) && (Address >= ADDR_FLASH_SECTOR_3_BANK1)) || \
          ((Address < ADDR_FLASH_SECTOR_4_BANK2) && (Address >= ADDR_FLASH_SECTOR_3_BANK2)))
  {
    sector = FLASH_SECTOR_3;
  }
  else if(((Address < ADDR_FLASH_SECTOR_5_BANK1) && (Address >= ADDR_FLASH_SECTOR_4_BANK1)) || \
          ((Address < ADDR_FLASH_SECTOR_5_BANK2) && (Address >= ADDR_FLASH_SECTOR_4_BANK2)))
  {
    sector = FLASH_SECTOR_4;
  }
  else if(((Address < ADDR_FLASH_SECTOR_6_BANK1) && (Address >= ADDR_FLASH_SECTOR_5_BANK1)) || \
          ((Address < ADDR_FLASH_SECTOR_6_BANK2) && (Address >= ADDR_FLASH_SECTOR_5_BANK2)))
  {
    sector = FLASH_SECTOR_5;
  }
  else if(((Address < ADDR_FLASH_SECTOR_7_BANK1) && (Address >= ADDR_FLASH_SECTOR_6_BANK1)) || \
          ((Address < ADDR_FLASH_SECTOR_7_BANK2) && (Address >= ADDR_FLASH_SECTOR_6_BANK2)))
  {
    sector = FLASH_SECTOR_6;
  }
  else if(((Address < ADDR_FLASH_SECTOR_0_BANK2) && (Address >= ADDR_FLASH_SECTOR_7_BANK1)) || \
          ((Address < FLASH_END_ADDR) && (Address >= ADDR_FLASH_SECTOR_7_BANK2)))
  {
     sector = FLASH_SECTOR_7;
  }
  else
  {
    sector = FLASH_SECTOR_7;
  }

  return sector;
}
