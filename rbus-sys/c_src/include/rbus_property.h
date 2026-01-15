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
 * @file        rubs_property.h
 * @brief       rbusProperty
 * @defgroup    rbusProperty
 * @brief       An rbus property is a name/value pair.  It allows assigning a name (e.g. path) to an rbus value.
 *              An rbusProperty_t is a reference counted handle to an rbus property.
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

#ifndef RBUS_PROPERTY_H
#define RBUS_PROPERTY_H

#include "rbus_value.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief       A handle to an rbus property.
 */
typedef struct _rbusProperty* rbusProperty_t;

/** @fn void rbusProperty_Init(rbusProperty_t* pproperty, char const* name, rbusValue_t value)
 *  @brief  Allocate and initialize a property.
 *          This automatically retains ownership of the property. 
 *          It's the caller's responsibility to release ownership by
 *          calling rbusProperty_Release once it's done with it.
 *  @param  pproperty Optional reference to an address where the new property will be assigned.
 *          The caller is responsible for releasing the property with rbusProperty_Release
 *  @param  name Optional name to assign the property.  The name is dublicated/copied.  
 *          If NULL is passed the property's name will be NULL.
 *  @param  value Optional value to assign the property.  The property will retain ownership of the value.
 *          If the value is NULL, the property's value will be NULL.
 *  @return The new property
 */
rbusProperty_t rbusProperty_Init(rbusProperty_t* pproperty, char const* name, rbusValue_t value);

/** @name rbusProperty_Init[Type]
 *  @brief  These function allocate and initialize a property 
 *          to a value with a specific type and data.
 *          This automatically retains ownership of the property. 
 *          It's the caller's responsibility to release ownership by
 *          calling rbusProperty_Release once it's done with it.
 *  @param name Optional name to assign the property.  The name is dublicated/copied.  
 *          If NULL is passed the property's name will be NULL.
 *  @param value The type specific data to set
 * @return The new property
 */
///@{
rbusProperty_t rbusProperty_InitBoolean(char const* name, bool b);
rbusProperty_t rbusProperty_InitChar(char const* name, char c);
rbusProperty_t rbusProperty_InitByte(char const* name, unsigned char u);
rbusProperty_t rbusProperty_InitInt8(char const* name, int8_t i8);
rbusProperty_t rbusProperty_InitUInt8(char const* name, uint8_t u8);
rbusProperty_t rbusProperty_InitInt16(char const* name, int16_t i16);
rbusProperty_t rbusProperty_InitUInt16(char const* name, uint16_t u16);
rbusProperty_t rbusProperty_InitInt32(char const* name, int32_t i32);
rbusProperty_t rbusProperty_InitUInt32(char const* name, uint32_t u32);
rbusProperty_t rbusProperty_InitInt64(char const* name, int64_t i64);
rbusProperty_t rbusProperty_InitUInt64(char const* name, uint64_t u64);
rbusProperty_t rbusProperty_InitSingle(char const* name, float f32);
rbusProperty_t rbusProperty_InitDouble(char const* name, double f64);
rbusProperty_t rbusProperty_InitTime(char const* name, rbusDateTime_t const* tv);
rbusProperty_t rbusProperty_InitString(char const* name, char const* s);
rbusProperty_t rbusProperty_InitBytes(char const* name, uint8_t const* bytes, int len);
rbusProperty_t rbusProperty_InitProperty(char const* name, struct _rbusProperty* property);
rbusProperty_t rbusProperty_InitObject(char const* name, struct _rbusObject* object);
///@}

/** @fn void rbusProperty_Retain(rbusProperty_t property)
 *  @brief Take shared ownership of the property.  This allows a property to have 
 *         multiple owners.  The first owner obtains ownership with rbusProperty_Init.
 *         Additional owners can be assigned afterwards with rbusProperty_Retain.  
 *         Each owner must call rbusProperty_Release once done using the property.
 *  @param property the property to retain
 */
void rbusProperty_Retain(rbusProperty_t property);

/** @fn void rbusProperty_Release(rbusProperty_t property)
 *  @brief Release ownership of the property.  This must be called when done using
 *         a property that was retained with either rbusProperty_Init or rbusProperty_Retain.
 *  @param property the property to release
 */
void rbusProperty_Release(rbusProperty_t property);

void rbusProperty_Releases(int count, ...);

/** @fn void rbusProperty_Compare(rbusProperty_t property1, rbusProperty_t property2)
 *  @brief Compare two properties for equality.  They are equal if both their names and values are equal.
 *  @param property1 the first property to compare
 *  @param property2 the second property to compare
 *  @return The compare result where 0 is equal and non-zero if not equal.  
 */
int rbusProperty_Compare(rbusProperty_t property1, rbusProperty_t property2);

/** @fn char* rbusProperty_GetName(rbusProperty_t property)
 *  @brief Get the name of a property.  
 *  @param property A property.
 *  @return The name of the property.  To avoid copies, this is a reference to the underlying name.
 */ 
char const* rbusProperty_GetName(rbusProperty_t property);

/** @fn void rbusProperty_SetName(rbusProperty_t property, char const* name)
 *  @brief Set the name of a property.  
 *  @param property A property.
 *  @param name the name to set which will be duplicated/copied
 */ 
void rbusProperty_SetName(rbusProperty_t property, char const* name);

/** @fn rbusValue_t rbusProperty_GetValue(rbusProperty_t property)
 *  @brief Get the value of a property.  
 *  @param property A property.
 *  @return The value of the property.  If the caller intends to store this value, 
 *          it should take ownership by calling rbusValue_Retain and then
 *          when its done with it, call rbusValue_Release.
 */ 
rbusValue_t rbusProperty_GetValue(rbusProperty_t property);

/** @fn void rbusProperty_SetValue(rbusProperty_t property, rbusValue_t value)
 *  @brief Set the value of a property.  
 *  @param property A property.
 *  @param The value to set.  The property will retain ownership of the value.
 */ 
void rbusProperty_SetValue(rbusProperty_t property, rbusValue_t value);

/** @name rbusProperty_Get[Type]
 *  @brief  These functions get the value of a property to a specific type and data.
 *  @return The type specific data
 */
///@{
bool rbusProperty_GetBoolean(rbusProperty_t property);
char rbusProperty_GetChar(rbusProperty_t property);
unsigned char rbusProperty_GetByte(rbusProperty_t property);
int8_t rbusProperty_GetInt8(rbusProperty_t property);
uint8_t rbusProperty_GetUInt8(rbusProperty_t property);
int16_t rbusProperty_GetInt16(rbusProperty_t property);
uint16_t rbusProperty_GetUInt16(rbusProperty_t property);
int32_t rbusProperty_GetInt32(rbusProperty_t property);
uint32_t rbusProperty_GetUInt32(rbusProperty_t property);
int64_t rbusProperty_GetInt64(rbusProperty_t property);
uint64_t rbusProperty_GetUInt64(rbusProperty_t property);
float rbusProperty_GetSingle(rbusProperty_t property);
double rbusProperty_GetDouble(rbusProperty_t property);
rbusDateTime_t const* rbusProperty_GetTime(rbusProperty_t property);
char const* rbusProperty_GetString(rbusProperty_t property, int* len);
uint8_t const* rbusProperty_GetBytes(rbusProperty_t property, int* len);
struct _rbusProperty* rbusProperty_GetProperty(rbusProperty_t property);
struct _rbusObject* rbusProperty_GetObject(rbusProperty_t property);
///@}

/** @name rbusProperty_Get[Type]Ex
 * @brief These functions check that the type being requested matches the value's actual type,
 *        and returns the data if it does.  If the type does not match, an error is returned.
 * @param value A property containing the value to get data from.
 * @param value Type specific data to return
 * @return error code as defined by rbusValueError_t.
 *        Possible errors are: RBUS_VALUE_ERROR_TYPE
 */
///@{
rbusValueError_t rbusProperty_GetBooleanEx(rbusProperty_t property, bool* b);
rbusValueError_t rbusProperty_GetCharEx(rbusProperty_t property, char* c);
rbusValueError_t rbusProperty_GetByteEx(rbusProperty_t property, unsigned char* u);
rbusValueError_t rbusProperty_GetInt8Ex(rbusProperty_t property, int8_t* i8);
rbusValueError_t rbusProperty_GetUInt8Ex(rbusProperty_t property, uint8_t* u8);
rbusValueError_t rbusProperty_GetInt16Ex(rbusProperty_t property, int16_t* i16);
rbusValueError_t rbusProperty_GetUInt16Ex(rbusProperty_t property, uint16_t* u16);
rbusValueError_t rbusProperty_GetInt32Ex(rbusProperty_t property, int32_t* i32);
rbusValueError_t rbusProperty_GetUInt32Ex(rbusProperty_t property, uint32_t* u32);
rbusValueError_t rbusProperty_GetInt64Ex(rbusProperty_t property, int64_t* i64);
rbusValueError_t rbusProperty_GetUInt64Ex(rbusProperty_t property, uint64_t* u64);
rbusValueError_t rbusProperty_GetSingleEx(rbusProperty_t property, float* f32);
rbusValueError_t rbusProperty_GetDoubleEx(rbusProperty_t property, double* f64);
rbusValueError_t rbusProperty_GetTimeEx(rbusProperty_t property, rbusDateTime_t const** tv);
rbusValueError_t rbusProperty_GetStringEx(rbusProperty_t property, char const** s, int* len);
rbusValueError_t rbusProperty_GetBytesEx(rbusProperty_t property, uint8_t const** bytes, int* len);
rbusValueError_t rbusProperty_GetPropertyEx(rbusProperty_t property, struct _rbusProperty** prop);
rbusValueError_t rbusProperty_GetObjectEx(rbusProperty_t property, struct _rbusObject** obj);
///@}

/** @name rbusProperty_Set[Type]
 *  @brief  These functions set the value of a property to a specific type and data.
 *  @param property A property.
 *  @param value The type specific data to set
 */
///@{
void rbusProperty_SetBoolean(rbusProperty_t property, bool b);
void rbusProperty_SetChar(rbusProperty_t property, char c);
void rbusProperty_SetByte(rbusProperty_t property, unsigned char u);
void rbusProperty_SetInt8(rbusProperty_t property, int8_t i8);
void rbusProperty_SetUInt8(rbusProperty_t property, uint8_t u8);
void rbusProperty_SetInt16(rbusProperty_t property, int16_t i16);
void rbusProperty_SetUInt16(rbusProperty_t property, uint16_t u16);
void rbusProperty_SetInt32(rbusProperty_t property, int32_t i32);
void rbusProperty_SetUInt32(rbusProperty_t property, uint32_t u32);
void rbusProperty_SetInt64(rbusProperty_t property, int64_t i64);
void rbusProperty_SetUInt64(rbusProperty_t property, uint64_t u64);
void rbusProperty_SetSingle(rbusProperty_t property, float f32);
void rbusProperty_SetDouble(rbusProperty_t property, double f64);
void rbusProperty_SetTime(rbusProperty_t property, rbusDateTime_t const* tv);
void rbusProperty_SetString(rbusProperty_t property, char const* s);
void rbusProperty_SetBytes(rbusProperty_t property, uint8_t const* bytes, int len);
void rbusProperty_SetProperty(rbusProperty_t property, struct _rbusProperty* p);
void rbusProperty_SetObject(rbusProperty_t property, struct _rbusObject* o);
///@}

/** @name rbusProperty_Append[Type]
 *  @brief  These function allocate and initialize a new property 
 *          with a value initialized with a specific type and data
 *          and appends this new property to the property param if
 *          the property param is not NULL.  
 *          This automatically retains ownership of the new property. 
 *          If the property param was NULL, it is the responsibility
 *          of the caller to call rbusProperty_Release to release it.
 *          If the propery param was not NULL, the new property will
 *          be automatically released when the first property in the
 *          list being appended to is release.
 *  @param property Optional property to append a new property to.
 *  @param name Optional name to assign the new property.  The name is dublicated/copied.  
 *          If NULL is passed the property's name will be NULL.
 *  @param value The type specific data to set
 * @return The new property.  If the property param was NULL, the called must release this.  
 */
///@{
rbusProperty_t rbusProperty_AppendBoolean(rbusProperty_t property, char const* name, bool b);
rbusProperty_t rbusProperty_AppendChar(rbusProperty_t property, char const* name, char c);
rbusProperty_t rbusProperty_AppendByte(rbusProperty_t property, char const* name, unsigned char u);
rbusProperty_t rbusProperty_AppendInt8(rbusProperty_t property, char const* name, int8_t i8);
rbusProperty_t rbusProperty_AppendUInt8(rbusProperty_t property, char const* name, uint8_t u8);
rbusProperty_t rbusProperty_AppendInt16(rbusProperty_t property, char const* name, int16_t i16);
rbusProperty_t rbusProperty_AppendUInt16(rbusProperty_t property, char const* name, uint16_t u16);
rbusProperty_t rbusProperty_AppendInt32(rbusProperty_t property, char const* name, int32_t i32);
rbusProperty_t rbusProperty_AppendUInt32(rbusProperty_t property, char const* name, uint32_t u32);
rbusProperty_t rbusProperty_AppendInt64(rbusProperty_t property, char const* name, int64_t i64);
rbusProperty_t rbusProperty_AppendUInt64(rbusProperty_t property, char const* name, uint64_t u64);
rbusProperty_t rbusProperty_AppendSingle(rbusProperty_t property, char const* name, float f32);
rbusProperty_t rbusProperty_AppendDouble(rbusProperty_t property, char const* name, double f64);
rbusProperty_t rbusProperty_AppendTime(rbusProperty_t property, char const* name, rbusDateTime_t const* tv);
rbusProperty_t rbusProperty_AppendString(rbusProperty_t property, char const* name, char const* s);
rbusProperty_t rbusProperty_AppendBytes(rbusProperty_t property, char const* name, uint8_t const* bytes, int len);
rbusProperty_t rbusProperty_AppendProperty(rbusProperty_t property, char const* name, struct _rbusProperty* p);
rbusProperty_t rbusProperty_AppendObject(rbusProperty_t property, char const* name, struct _rbusObject* o);
///@}

/** @fn char* rbusProperty_GetNext(rbusProperty_t property)
 *  @brief Get the next property from the list.  Properties can be linked together into a list.
 *         Given a property in that list, the next property in the list can be obtained with this method. 
 *  @param property A property.
 *  @return The next property in the list.  If the caller intends to store this property, 
 *          it should take ownership by calling rbusProperty_Retain and then
 *          when its done with it, call rbusProperty_Release.
 */  
rbusProperty_t rbusProperty_GetNext(rbusProperty_t property);

/** @fn void rbusProperty_SetNext(rbusProperty_t property, rbusProperty_t next)
 *  @brief Set the next property in the list.  Properties can be linked together into a list.
 *         Given a property in that list, the next property in the list can be set with this method. 
 *         If next had been previously set, then ownership of the former next property is released.
 *  @param property A property.
 *  @param next A property to be set as the next in the list.  
           next can be a list itself, in which case the list is Nexted.
           next can be NULL, in which case the list is terminated.
           setting NULL is also a way to clear the list.
 */ 
void rbusProperty_SetNext(rbusProperty_t property, rbusProperty_t next);

/** @fn void rbusProperty_Append(rbusProperty_t property, rbusProperty_t back)
 *  @brief Append a property to the end of a property list.  
           Ownership of the property being appended will be retained.
 *  @param property A property.
 *  @param back A property to append to the end of the list.
           If back is NULL, then no action is taken.
 */ 
void rbusProperty_Append(rbusProperty_t property, rbusProperty_t back);

#define rbusProperty_PushBack(prop, back) rbusProperty_Append((prop),(back))

/** @fn uint32_t rbusProperty_Count(rbusProperty_t property)
 *  @brief Return the number or properties in the list
 *  @param property A property (the first in list).
 *  @return The number of properties in the list.
 */ 
uint32_t rbusProperty_Count(rbusProperty_t property);

void rbusProperty_fwrite(rbusProperty_t prop, int depth, FILE* fout);

#ifdef __cplusplus
}
#endif
#endif

/** @} */
