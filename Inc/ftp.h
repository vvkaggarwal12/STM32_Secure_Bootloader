#ifndef __FTP__
#define __FTP__

/**
  * @brief This function sets the Stack Pointer and Program Counter to jump into a function
  * @param  vector_address Start Address (where to jump)
  * @retval void
  */
void jump_to_function(uint8_t *vector_address);

void parse_data_received(uint8_t data);

/**
  * @brief This function returns from an interrupt and launches the user application code
  * @param  applicationVectorAddress Start address of the user application (active slot+offset: vectors)
  * @param  exitFunctionAddress Function to jump into the user application code
  * @param  address Function to jump into the BL code in case of exit_sticky usage
  * @param  magic number used by BL code in case of exit_sticky usage
  * @retval void
  */
void launch_application(uint32_t applicationVectorAddress, uint32_t exitFunctionAddress);

#endif /* __FTP__ */ 
