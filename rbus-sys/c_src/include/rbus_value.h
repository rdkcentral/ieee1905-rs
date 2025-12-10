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

/**
 * @file        rubs_value.h
 * @brief       rbusValue
 * @defgroup    rbusValue
 * @brief       An rbus value is a variant data type representing a fundamental piece of data passed through rbus.
 *              An rbusValue_t is a reference counted handle to an rbus value.  
  * 
 * This API is not thread-safe.  
 * All instances of types rbusValue_t, rbusProperty_t, and rbusObject_t are referenced counted.
 * Instances of these types may have private references to other instances of these types.
 * There are read methods in this api that return references to these private instances.
 * There are write methods in this api that release current references and retain new ones. 
 * When this happens any reference held by the user becomes unlinked from the parent instance.
 * The instance will also be destroyed unless the user retains it for themselves.
 * @{
 */

#ifndef RBUS_VALUE_H
#define RBUS_VALUE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief       The value types that can be contained inside an rbusValue_t
 * @enum        rbusValueType_t
 */
typedef enum
{
    RBUS_BOOLEAN  = 0x500,  /**< bool true or false */
    RBUS_CHAR,              /**< char of size 1 byte*/
    RBUS_BYTE,              /**< unsigned char */
    RBUS_INT8,              /**< 8 bit int */
    RBUS_UINT8,             /**< 8 bit unsigned int */
    RBUS_INT16,             /**< 16 bit int */
    RBUS_UINT16,            /**< 16 bit unsigned int */
    RBUS_INT32,             /**< 32 bit int */
    RBUS_UINT32,            /**< 32 bit unsigned int */
    RBUS_INT64,             /**< 64 bit int */
    RBUS_UINT64,            /**< 64 bit unsigned int */
    RBUS_SINGLE,            /**< 32 bit float */
    RBUS_DOUBLE,            /**< 64 bit float */
    RBUS_DATETIME,          /**< rbusDateTime_t structure for Date/Time */
    RBUS_STRING,            /**< null terminated C style string */
    RBUS_BYTES,             /**< byte array */
    RBUS_PROPERTY,          /**< property instance */
    RBUS_OBJECT,            /**< object instance */
    RBUS_NONE
} rbusValueType_t;

typedef enum
{
    RBUS_VALUE_ERROR_SUCCESS = 0,
    RBUS_VALUE_ERROR_TYPE,
    RBUS_VALUE_ERROR_NOT_FOUND,
    RBUS_VALUE_ERROR_NULL
} rbusValueError_t;

typedef struct _rbusTimeZone {
    int32_t m_tzhour;
    int32_t m_tzmin;
    bool m_isWest;
} rbusTimeZone_t ;


struct tm32
{
  int32_t tm_sec;			/* Seconds.	[0-60] (1 leap second) */
  int32_t tm_min;			/* Minutes.	[0-59] */
  int32_t tm_hour;			/* Hours.	[0-23] */
  int32_t tm_mday;			/* Day.		[1-31] */
  int32_t tm_mon;			/* Month.	[0-11] */
  int32_t tm_year;			/* Year	- 1900.  */
  int32_t tm_wday;			/* Day of week.	[0-6] */
  int32_t tm_yday;			/* Days in year.[0-365]	*/
  int32_t tm_isdst;			/* DST.		[-1/0/1]*/
};

typedef struct _rbusDateTime {
    struct tm32       m_time;
    rbusTimeZone_t  m_tz;
} rbusDateTime_t;

/**
 * @brief       A handle to an rbus value.
 */
typedef struct _rbusValue* rbusValue_t;

/**
 * @brief       A handle to an rbus object.
 * @ingroup     rbusObject
 */
typedef struct _rbusObject* rbusObject_t;

/**
 * @brief       A handle to an rbus property.
 * @ingroup     rbusProperty
 */
typedef struct _rbusProperty* rbusProperty_t;

/** @fn void rbusValue_Init(rbusValue_t* pvalue)
 *  @brief  Allocate and initialize a value to an empty state
 *          with its type set to RBUS_NONE and data set to NULL.
 *          This automatically retains ownership of the value. 
 *          It's the caller's responsibility to release ownership by
 *          calling rbusValue_Release once it's done with it.
 *  @param  Optional pvalue reference to an address where the new value will be assigned.
 *          The caller is responsible for releasing the value with rbusValue_Release
 *  @return The new value
 */
rbusValue_t rbusValue_Init(rbusValue_t* pvalue);

/** @name rbusValue_Get[Type]
 * @brief These functions returns the data stored in the value according to their type.
 *        The data is not coerced to the type, thus the caller should ensure
 *        the value's actual type matches the function being called.  The caller can 
 *        call rbusValue_GetType to get the type.
 * @param value A value to get data from.
 * @return The data as a specific type. This is meant to be a const accessor. 
 *         To avoid large copies, if the type is a buffer or struct type, 
 *         a const pointer to the actual data is returned. 
 */
///@{
rbusValue_t rbusValue_InitBoolean(bool b);
rbusValue_t rbusValue_InitChar(char c);
rbusValue_t rbusValue_InitByte(unsigned char u);
rbusValue_t rbusValue_InitInt8(int8_t i8);
rbusValue_t rbusValue_InitUInt8(uint8_t u8);
rbusValue_t rbusValue_InitInt16(int16_t i16);
rbusValue_t rbusValue_InitUInt16(uint16_t u16);
rbusValue_t rbusValue_InitInt32(int32_t i32);
rbusValue_t rbusValue_InitUInt32(uint32_t u32);
rbusValue_t rbusValue_InitInt64(int64_t i64);
rbusValue_t rbusValue_InitUInt64(uint64_t u64);
rbusValue_t rbusValue_InitSingle(float f32);
rbusValue_t rbusValue_InitDouble(double f64);
rbusValue_t rbusValue_InitTime(rbusDateTime_t const* tv);
rbusValue_t rbusValue_InitString(char const* s);
rbusValue_t rbusValue_InitBytes(uint8_t const* bytes, int len);
rbusValue_t rbusValue_InitProperty(struct _rbusProperty* property);
rbusValue_t rbusValue_InitObject(struct _rbusObject* object);
///@}

/** @fn void rbusValue_Retain(rbusValue_t value)
 *  @brief Take shared ownership of the value.  This allows a value to have 
 *         multiple owners.  The first owner obtains ownership with rbusValue_Init.
 *         Additional owners can be assigned afterwards with rbusValue_Retain.  
 *         Each owner must call rbusValue_Release once done using the value.
 *  @param value the value to retain
 */
void rbusValue_Retain(rbusValue_t value);

/** @fn void rbusValue_Release(rbusValue_t value)
 *  @brief Release ownership of the value.  This must be called when done using
 *         a value that was retained with either rbusValue_Init or rbusValue_Retain.
 *  @param value the value to release
 */
void rbusValue_Release(rbusValue_t value);

void rbusValue_Releases(int count, ...);

/** @fn void rbusValue_Compare(rbusValue_t value1, rbusValue_t value2)
 *  @brief Compare two values for equality.  They are equal if both the type and data are equal.
 *  @param value1 the first value to compare
 *  @param value2 the second value to compare
 *  @return The compare result where 0 is equal and non-zero if not equal.  If value1
 */
int rbusValue_Compare(rbusValue_t value1, rbusValue_t value2);

/** @fn void rbusValue_SetPointer(rbusValue_t value1, rbusValue_t value2)
 *  @brief Set value1 pointer to value2 while handling the ref count.
 *  @param value1 the first value to swap
 *  @param value2 the second value to swap
 */
void rbusValue_SetPointer(rbusValue_t* value1, rbusValue_t value2);

/** @fn void rbusValue_Copy(rbusValue_t dest, rbusValue_t source)
 *  @brief Copy data from source to dest
 *  @param dest destination to copy data into
 *  @param source source of data to copy from
 */
void rbusValue_Copy(rbusValue_t dest, rbusValue_t source);

/** @fn char* rbusValue_ToString(rbusValue_t value, char* buf, size_t buflen)
 *  @brief Returns a null terminated string representing the data of the value.  
 *         Parameters buf and buflen are optional and allow the caller to pass in a buffer 
 *          to write the string to.  If parameter buf is NULL, this method will allocate a buffer
 *          to write the string to and the caller should call free to deallocate the buffer.
 *          For DateTime datatype, below ISO-8601 formats as per TR-069_Amendment-6 will be used for printing.
 *          YYYY-MM-DDThh:mm:ssZ
 *          YYYY-MM-DDThh:mm:ss+00:00
 *          YYYY-MM-DDThh:mm:ss-00:00
 *  @param value the value to convert to a string
 *  @param buf optional buffer to write the string to
 *  @param buflen the length of buf if buf was supplied, otherwise ignored
 *  @return A null-terminated string.  The caller must call free on this if parameter buf was NULL.
 */
char* rbusValue_ToString(rbusValue_t value, char* buf, size_t buflen);

/** @fn char* rbusValue_ToDebugString(rbusValue_t value, char* buf, size_t buflen)
 *  @brief Returns a null terminated string representing the type and data of the value.  
 *         Parameters buf and buflen are optional and allow the caller to pass in a buffer 
 *          to write the string to.  If parameter buf is NULL, this method will allocate a buffer
 *          to write the string to and the caller should call free to deallocate the buffer.
 *  @param value the value to convert to a string
 *  @param buf optional buffer to write the string to
 *  @param buflen the length of buf if buf was supplied, otherwise ignored
 *  @return A null-terminated string.  The caller must call free on this if parameter buf was NULL.
 */
char* rbusValue_ToDebugString(rbusValue_t value, char* buf, size_t buflen);

/** @fn char* rbusValue_GetType(rbusValue_t value)
 *  @brief Get the type of a value.  
 *  @param value A value.
 *  @return The type of the value.
 */ 
rbusValueType_t rbusValue_GetType(rbusValue_t value);

/** @name rbusValue_Get[Type]
 * @brief These functions return the data stored in the value by type.
 *        The data is not coerced to the type, thus the caller should ensure
 *        the value's actual type matches the function being called.  The caller can 
 *        call rbusValue_GetType to get the type.
 * @param value A value to get data from.
 * @return The data as a specific type. This is meant to be a const accessor. 
 *         To avoid large copies, if the type is a buffer or struct type, 
 *         a const pointer to the actual data is returned. 
 */
///@{
bool rbusValue_GetBoolean(rbusValue_t value);
char rbusValue_GetChar(rbusValue_t value);
unsigned char rbusValue_GetByte(rbusValue_t value);
int8_t rbusValue_GetInt8(rbusValue_t value);
uint8_t rbusValue_GetUInt8(rbusValue_t value);
int16_t rbusValue_GetInt16(rbusValue_t value);
uint16_t rbusValue_GetUInt16(rbusValue_t value);
int32_t rbusValue_GetInt32(rbusValue_t value);
uint32_t rbusValue_GetUInt32(rbusValue_t value);
int64_t rbusValue_GetInt64(rbusValue_t value);
uint64_t rbusValue_GetUInt64(rbusValue_t value);
float rbusValue_GetSingle(rbusValue_t value);
double rbusValue_GetDouble(rbusValue_t value);
rbusDateTime_t const* rbusValue_GetTime(rbusValue_t value);
char const* rbusValue_GetString(rbusValue_t value, int* len);
uint8_t const* rbusValue_GetBytes(rbusValue_t value, int* len);
struct _rbusProperty* rbusValue_GetProperty(rbusValue_t value);
struct _rbusObject* rbusValue_GetObject(rbusValue_t value);
///@}

/** @name rbusValue_Get[Type]Ex
* @brief These functions check that the type being requested matches the value's actual type,
 *        and returns the data if it does.  If the type does not match, an error is returned.
  * @param value A value to get data from.
 * @param value Type specific data to return
 * @return error code as defined by rbusValueError_t.
 *        Possible errors are: RBUS_VALUE_ERROR_TYPE
 */
///@{
rbusValueError_t rbusValue_GetBooleanEx(rbusValue_t value, bool* b);
rbusValueError_t rbusValue_GetCharEx(rbusValue_t v, char* c);
rbusValueError_t rbusValue_GetByteEx(rbusValue_t v, unsigned char* u);
rbusValueError_t rbusValue_GetInt8Ex(rbusValue_t v, int8_t* i8);
rbusValueError_t rbusValue_GetUInt8Ex(rbusValue_t v, uint8_t* u8);
rbusValueError_t rbusValue_GetInt16Ex(rbusValue_t value, int16_t* i16);
rbusValueError_t rbusValue_GetUInt16Ex(rbusValue_t value, uint16_t* u16);
rbusValueError_t rbusValue_GetInt32Ex(rbusValue_t value, int32_t* i32);
rbusValueError_t rbusValue_GetUInt32Ex(rbusValue_t value, uint32_t* u32);
rbusValueError_t rbusValue_GetInt64Ex(rbusValue_t value, int64_t* i64);
rbusValueError_t rbusValue_GetUInt64Ex(rbusValue_t value, uint64_t* u64);
rbusValueError_t rbusValue_GetSingleEx(rbusValue_t value, float* f32);
rbusValueError_t rbusValue_GetDoubleEx(rbusValue_t value, double* f64);
rbusValueError_t rbusValue_GetTimeEx(rbusValue_t value, rbusDateTime_t const** tv);
rbusValueError_t rbusValue_GetStringEx(rbusValue_t value, char const** s, int* len);
rbusValueError_t rbusValue_GetBytesEx(rbusValue_t value, uint8_t const** bytes, int* len);
rbusValueError_t rbusValue_GetPropertyEx(rbusValue_t value, struct _rbusProperty** property);
rbusValueError_t rbusValue_GetObjectEx(rbusValue_t value, struct _rbusObject** object);
///@}

/** @name rbusValue_Set[Type]
 * @brief These functions set the type and data of a value.
 * @param value A value to set.
 * @param data The type specific data to set on the value.
 */
///@{
void rbusValue_SetBoolean(rbusValue_t value, bool b);
void rbusValue_SetChar(rbusValue_t v, char c);
void rbusValue_SetByte(rbusValue_t v, unsigned char u);
void rbusValue_SetInt8(rbusValue_t v, int8_t i8);
void rbusValue_SetUInt8(rbusValue_t v, uint8_t u8);
void rbusValue_SetInt16(rbusValue_t value, int16_t i16);
void rbusValue_SetUInt16(rbusValue_t value, uint16_t u16);
void rbusValue_SetInt32(rbusValue_t value, int32_t i32);
void rbusValue_SetUInt32(rbusValue_t value, uint32_t u32);
void rbusValue_SetInt64(rbusValue_t value, int64_t i64);
void rbusValue_SetUInt64(rbusValue_t value, uint64_t u64);
void rbusValue_SetSingle(rbusValue_t value, float f32);
void rbusValue_SetDouble(rbusValue_t value, double f64);
void rbusValue_SetTime(rbusValue_t value, rbusDateTime_t const* tv);
void rbusValue_SetString(rbusValue_t value, char const* s);
void rbusValue_SetBytes(rbusValue_t value, uint8_t const* bytes, int len);
void rbusValue_SetProperty(rbusValue_t value, struct _rbusProperty* property);
void rbusValue_SetObject(rbusValue_t value, struct _rbusObject* object);
///@}

void rbusValue_Swap(rbusValue_t* v1, rbusValue_t* v2);
///  @brief rbusValue_SetFromString sets the value's type to given type and data to appropriate by converting the string
/** 
 *  @brief Sets the type and data of a value by converting a string representation of the data to a specific typed data.
 *  @param value A value to set.
 *  @param type The type of data represented by the input string and to which the value will be assigned.
 *  @param str A string representation of the data which will be coerced to the type specified by the type param and assigned to the value.
 *  @return bool true if this function succeeds to coerce the type and set the value or false if it fails
 */
bool rbusValue_SetFromString(rbusValue_t value, rbusValueType_t type, const char* str);

/** @fn void rbusValue_fwrite(rbusValue_t obj, int depth, FILE* fout)
 *  @brief A debug utility function to write the value as a string to a file stream.
 */
void rbusValue_fwrite(rbusValue_t obj, int depth, FILE* fout);



/**
 *  @brief Convert a local "struct tm" type to an explicit length version, which allows 64/32 bit platform message interchange
 *  @param invalue An incoming struct tm
 *  @param outvalue An outgoing explicit length time structure
 */
void rbusValue_MarshallTMtoRBUS(rbusDateTime_t* outvalue, const struct tm* invalue);

/**
 *  @brief Convert an explicit length time structure to a local "struct tm", which allows 64/32 bit platform message interchange
 *  @param invalue An incoming explicit length time structure
 *  @param outvalue An outgoing struct tm
 */
void rbusValue_UnMarshallRBUStoTM(struct tm* outvalue, const rbusDateTime_t* invalue);

#ifdef __cplusplus
}
#endif
#endif

/** @} */
