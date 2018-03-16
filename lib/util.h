/*
 * util.h
 *
 *  Created on: 14 Mar 2018
 *      Author: samuelh
 */

#ifndef LIB_UTIL_H_
#define LIB_UTIL_H_

uint16_t get_uint16_from_buf (uint8_t* buf);
int16_t get_int16_from_buf (uint8_t* buf);

uint32_t get_uint32_from_buf (uint8_t* buf);
int32_t get_int32_from_buf (uint8_t* buf);

uint64_t get_uint64_from_buf (uint8_t* buf);
int64_t get_int64_from_buf (uint8_t* buf);

#endif /* LIB_UTIL_H_ */
