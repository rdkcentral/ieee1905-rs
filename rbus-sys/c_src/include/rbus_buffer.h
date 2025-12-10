/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef RBUS_BUFFER_H
#define RBUS_BUFFER_H

#include "rbus.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _rbusBuffer
{
    int             lenAlloc;
    int             posWrite;
    int             posRead;
    uint8_t*        data;
    uint8_t         block1[64];
} *rbusBuffer_t;

char const* rbusValueType_ToDebugString(rbusValueType_t type);

/*GetV,GetL,SetTLV are temporary until we are able to switch to Decode/Encode*/
uint8_t const* rbusValue_GetV(rbusValue_t v);
uint32_t rbusValue_GetL(rbusValue_t v);
void rbusValue_SetTLV(rbusValue_t v, rbusValueType_t type, uint32_t length, void const* value);

/*Decode/Encode can be used once we disable message pack and change ccsp
    Currently we push/pop name, type, value separately with rtMessage.
    This will change where we pass the rbusBuffer_t raw binary to the socket
    and that will require changes in ccsp_base_api/message_bus I imagine
*/
int rbusValue_Decode(rbusValue_t* value, rbusBuffer_t const buff);
void rbusValue_Encode(rbusValue_t value, rbusBuffer_t buff);

void rbusFilter_Encode(rbusFilter_t filter, rbusBuffer_t buff);
int rbusFilter_Decode(rbusFilter_t* filter, rbusBuffer_t const buff);

void rbusBuffer_Create(rbusBuffer_t* buff);
void rbusBuffer_Destroy(rbusBuffer_t buff);
void rbusBuffer_Reserve(rbusBuffer_t buff, int len);
void rbusBuffer_Write(rbusBuffer_t buff, void const* data, int len);
void rbusBuffer_WriteTypeLengthValue(rbusBuffer_t buff, rbusValueType_t type, uint16_t length, void const* value);
void rbusBuffer_WriteBooleanTLV(rbusBuffer_t buff, bool b);
void rbusBuffer_WriteCharTLV(rbusBuffer_t buff, char c);
void rbusBuffer_WriteByteTLV(rbusBuffer_t buff, unsigned char u);
void rbusBuffer_WriteInt8TLV(rbusBuffer_t buff, int8_t i8);
void rbusBuffer_WriteUInt8TLV(rbusBuffer_t buff, uint8_t u8);
void rbusBuffer_WriteInt16TLV(rbusBuffer_t buff, int16_t i16);
void rbusBuffer_WriteUInt16TLV(rbusBuffer_t buff, uint16_t u16);
void rbusBuffer_WriteInt32TLV(rbusBuffer_t buff, int32_t i32);
void rbusBuffer_WriteUInt32TLV(rbusBuffer_t buff, uint32_t u32);
void rbusBuffer_WriteInt64TLV(rbusBuffer_t buff, int64_t i64);
void rbusBuffer_WriteUInt64TLV(rbusBuffer_t buff, uint64_t u64);
void rbusBuffer_WriteSingleTLV(rbusBuffer_t buff, float f32);
void rbusBuffer_WriteDoubleTLV(rbusBuffer_t buff, double f64);
void rbusBuffer_WriteStringTLV(rbusBuffer_t buff, char const* s, int len);
void rbusBuffer_WriteDateTimeTLV(rbusBuffer_t buff, rbusDateTime_t const* tv);
void rbusBuffer_WriteBytesTLV(rbusBuffer_t buff, uint8_t* bytes, int len);
/*The Read functions return 0 on success or -1 on failure (reading that would result in memory overrun)*/
int rbusBuffer_Read(rbusBuffer_t const buff, void* data, int len);
int rbusBuffer_ReadBoolean(rbusBuffer_t const buff, bool* b);
int rbusBuffer_ReadChar(rbusBuffer_t const buff, char* c);
int rbusBuffer_ReadByte(rbusBuffer_t const buff, unsigned char* u);
int rbusBuffer_ReadInt8(rbusBuffer_t const buff, int8_t* i8);
int rbusBuffer_ReadUInt8(rbusBuffer_t const buff, uint8_t* u8);
int rbusBuffer_ReadInt16(rbusBuffer_t const buff, int16_t* i16);
int rbusBuffer_ReadUInt16(rbusBuffer_t const buff, uint16_t* u16);
int rbusBuffer_ReadInt32(rbusBuffer_t const buff, int32_t* i32);
int rbusBuffer_ReadUInt32(rbusBuffer_t const buff, uint32_t* u32);
int rbusBuffer_ReadInt64(rbusBuffer_t const buff, int64_t* i64);
int rbusBuffer_ReadUInt64(rbusBuffer_t const buff, uint64_t* u64);
int rbusBuffer_ReadSingle(rbusBuffer_t const buff, float* f32);
int rbusBuffer_ReadDouble(rbusBuffer_t const buff, double* f64);
int rbusBuffer_ReadString(rbusBuffer_t const buff, char** s, int* len);/* caller must free *s */
int rbusBuffer_ReadDateTime(rbusBuffer_t const buff, rbusDateTime_t* tv);
int rbusBuffer_ReadBytes(rbusBuffer_t const buff, uint8_t** bytes, int* len);/* caller must free *bytes */

#ifdef __cplusplus
}
#endif
#endif
