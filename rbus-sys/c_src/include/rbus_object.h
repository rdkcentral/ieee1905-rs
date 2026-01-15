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
 * @file        rubs_object.h
 * @brief       rbusObject
 * @defgroup    rbusObject
 * @brief       An rbus object is a named collection of properties.
 *
 * An rbusObject_t is a reference counted handle to an rbus object.  
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

#ifndef RBUS_OBJECT_H
#define RBUS_OBJECT_H

#include "rbus_property.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef enum _rbusObjectType
{
    RBUS_OBJECT_SINGLE_INSTANCE,
    RBUS_OBJECT_MULTI_INSTANCE
}rbusObjectType_t;

/**
 * @brief       A handle to an rbus object.
 */
typedef struct _rbusObject* rbusObject_t;

/** @fn void rbusObject_Init(rbusObject_t* object, char const* name)
 *  @brief  Allocate, initialize, and take ownershipt of an object.
 *
 *  This automatically retains ownership of the object. 
 *  It's the caller's responsibility to release ownership by
 *  calling rbusObject_Release once it's done with it.
 *  @param  pobject reference to an address where the new object will be assigned.
 *          The caller is responsible for releasing the object with rbusObject_Release
 *  @param  name  optional name to assign the object.  The name is dublicated/copied.  
 *          If NULL is passed the object's name will be NULL.
 */
rbusObject_t rbusObject_Init(rbusObject_t* pobject, char const* name);

void rbusObject_InitMultiInstance(rbusObject_t* pobject, char const* name);

/** @fn void rbusObject_Retain(rbusObject_t object)
 *  @brief Take shared ownership of the object.
 *
 *  This allows an object to have multiple owners.  The first owner obtains ownership
 *  with rbusObject_Init. Additional owners can be assigned afterwards with rbusObject_Retain.
 *  Each owner must call rbusObject_Release once done using the object.
 *  @param object the object to retain
 */
void rbusObject_Retain(rbusObject_t object);

/** @fn void rbusObject_Release(rbusObject_t object)
 *  @brief Release ownership of the object.
 *
 *  This must be called when done using a object that was retained with either rbusObject_Init or rbusObject_Retain.
 *  @param object the object to release
 */
void rbusObject_Release(rbusObject_t object);

void rbusObject_Releases(int count, ...);

/** @fn void rbusObject_Compare(rbusObject_t object1, rbusObject_t object2)
 *  @brief Compare two objects for equality.  They are equal if both their names and values are equal.
 *  @param object1 the first object to compare
 *  @param object2 the second object to compare
 *  @param recursive compare all child and their descendants objects
 *  @return The compare result where 0 is equal and non-zero if not equal.  
 */
int rbusObject_Compare(rbusObject_t object1, rbusObject_t object2, bool recursive);

/** @fn char const* rbusObject_GetName(rbusObject_t object)
 *  @brief Get the name of a object.
 *  @param object An object.
 *  @return The name of the object.  To avoid copies, this is a reference to the underlying name.
 */
char const* rbusObject_GetName(rbusObject_t object);

/** @fn rbusObject_SetName(rbusObject_t object, char const* name)
 *  @brief Set the name of a object.
 *  @param object An object.
 *  @param name the name to set which will be duplicated/copied
 */ 
void rbusObject_SetName(rbusObject_t object, char const* name);

/** @fn rbusProperty_t rbusObject_GetProperties(rbusObject_t object)
 *  @brief Get the property list of an object.
 *  @param object An object.
 *  @return The property list of the object.
 */ 
rbusProperty_t rbusObject_GetProperties(rbusObject_t object);

/** @fn void rbusObject_SetProperties(rbusObject_t object, rbusProperty_t properties)
 *  @brief Set the property list of an object.
 *
 *  If a property list already exists on the object, then ownership of all properties in that list is released.
 *  @param object An object.
 *  @param properties A property list to set on the object.  Any existing propery list is released.
 */
void rbusObject_SetProperties(rbusObject_t object, rbusProperty_t properties);

/** @fn rbusProperty_t rbusObject_GetProperty(rbusObject_t object, char const* name)
 *  @brief Get a property by name from an object.
 *  @param object An object.
 *  @param name The name of the property to get.
 *  @return The property matching the name, or NULL if no match found.
 */ 
rbusProperty_t rbusObject_GetProperty(rbusObject_t object, char const* name);

/** @fn void rbusObject_SetProperty(rbusObject_t object, rbusProperty_t property)
 *  @brief Set a property on an object.
 *
 *  If a property with the same name already exists, its ownership released.
 *  @param object An object.
 *  @param property A property to set on the object.  The caller should set the name
           on this property before calling this method.
 */
void rbusObject_SetProperty(rbusObject_t object, rbusProperty_t property);

/** @fn rbusValue_t rbusObject_GetValue(rbusObject_t object, char const* name)
 *  @brief Get the value of a property by name from an object.
 *  @param object An object.
 *  @param name The name of the property to get the value of.
 *  @return The value of the property matching the name, or NULL if no match found.
 */ 
rbusValue_t rbusObject_GetValue(rbusObject_t object, char const* name);
rbusValue_t rbusObject_GetPropertyValue(rbusObject_t object, char const* name);

/** @fn void rbusObject_SetValue(rbusObject_t object, char const* name, rbusValue_t value)
 *  @brief Set the value of a property by name on an object.
 *
 * If a property with the same name does not exist, a new property is created.
 * Ownership of any previous property/value will be released.
 *  @param object An object.
 *  @param name the name of the property inside the object to set the value to
 *  @param value a value to set on the object's property
 */
void rbusObject_SetValue(rbusObject_t object, char const* name, rbusValue_t value);
void rbusObject_SetPropertyValue(rbusObject_t object, char const* name, rbusValue_t value);

/** @name rbusObject_GetValue[Type]
 *  @brief These functions get the type specific value of a property by name on an object.
 * 
 *  In order to prevent crashes, if the property name doesn't exist in the object,
 *  a warning will be logged and a default empty data will be returned.
 *  @param object An object.
 *  @param name the name of the property inside the object to set the value to
 *  @return the type specific data
 */
///@{
rbusValueError_t rbusObject_GetPropertyBoolean(rbusObject_t object, char const* name, bool* b);
rbusValueError_t rbusObject_GetPropertyInt8(rbusObject_t object, char const* name, int8_t* i8);
rbusValueError_t rbusObject_GetPropertyUInt8(rbusObject_t object, char const* name, uint8_t* u8);
rbusValueError_t rbusObject_GetPropertyInt16(rbusObject_t object, char const* name, int16_t* i16);
rbusValueError_t rbusObject_GetPropertyUInt16(rbusObject_t object, char const* name, uint16_t* u16);
rbusValueError_t rbusObject_GetPropertyInt32(rbusObject_t object, char const* name, int32_t* i32);
rbusValueError_t rbusObject_GetPropertyUInt32(rbusObject_t object, char const* name, uint32_t* u32);
rbusValueError_t rbusObject_GetPropertyInt64(rbusObject_t object, char const* name, int64_t* i64);
rbusValueError_t rbusObject_GetPropertyUInt64(rbusObject_t object, char const* name, uint64_t* u64);
rbusValueError_t rbusObject_GetPropertySingle(rbusObject_t object, char const* name, float* f32);
rbusValueError_t rbusObject_GetPropertyDouble(rbusObject_t object, char const* name, double* f64);
rbusValueError_t rbusObject_GetPropertyTime(rbusObject_t object, char const* name, rbusDateTime_t const** tv);
rbusValueError_t rbusObject_GetPropertyString(rbusObject_t object, char const* name, char const** s, int* len);
rbusValueError_t rbusObject_GetPropertyBytes(rbusObject_t object, char const* name, uint8_t const** bytes, int* len);
rbusValueError_t rbusObject_GetPropertyProperty(rbusObject_t object, char const* name, struct _rbusProperty** p);
rbusValueError_t rbusObject_GetPropertyObject(rbusObject_t object, char const* name, struct _rbusObject** o);
rbusValueError_t rbusObject_GetPropertyChar(rbusObject_t object, char const* name, char* c);
rbusValueError_t rbusObject_GetPropertyByte(rbusObject_t object, char const* name, unsigned char* c);
///@}

/** @name rbusObject_SetValue[Type]
 *  @brief These functions set the value of a property by name on an object, 
 * where the value is internally initialized with the corresponding type and data.
 * 
 * If a property with the same name does not exist, a new property is created.
 * Ownership of any previous property/value will be released.
 *  @param object An object.
 *  @param name the name of the property inside the object to set the value to
 *  @param value the type specific data to set on the object's property
 */
///@{
void rbusObject_SetPropertyBoolean(rbusObject_t object, char const* name, bool b);
void rbusObject_SetPropertyInt8(rbusObject_t object, char const* name, int8_t i8);
void rbusObject_SetPropertyUInt8(rbusObject_t object, char const* name, uint8_t u8);
void rbusObject_SetPropertyInt16(rbusObject_t object, char const* name, int16_t i16);
void rbusObject_SetPropertyUInt16(rbusObject_t object, char const* name, uint16_t u16);
void rbusObject_SetPropertyInt32(rbusObject_t object, char const* name, int32_t i32);
void rbusObject_SetPropertyUInt32(rbusObject_t object, char const* name, uint32_t u32);
void rbusObject_SetPropertyInt64(rbusObject_t object, char const* name, int64_t i64);
void rbusObject_SetPropertyUInt64(rbusObject_t object, char const* name, uint64_t u64);
void rbusObject_SetPropertySingle(rbusObject_t object, char const* name, float f32);
void rbusObject_SetPropertyDouble(rbusObject_t object, char const* name, double f64);
void rbusObject_SetPropertyTime(rbusObject_t object, char const* name, rbusDateTime_t const* tv);
void rbusObject_SetPropertyString(rbusObject_t object, char const* name, char const* s);
void rbusObject_SetPropertyBytes(rbusObject_t object, char const* name, uint8_t const* bytes, int len);
void rbusObject_SetPropertyProperty(rbusObject_t object, char const* name, struct _rbusProperty* p);
void rbusObject_SetPropertyObject(rbusObject_t object, char const* name, struct _rbusObject* o);
void rbusObject_SetPropertyChar(rbusObject_t object, char const* name, char c);
void rbusObject_SetPropertyByte(rbusObject_t object, char const* name, unsigned char c);
///@}

rbusObject_t rbusObject_GetParent(rbusObject_t object);
void rbusObject_SetParent(rbusObject_t object, rbusObject_t parent);

rbusObject_t rbusObject_GetChildren(rbusObject_t object);
void rbusObject_SetChildren(rbusObject_t object, rbusObject_t children);

rbusObject_t rbusObject_GetNext(rbusObject_t object);
void rbusObject_SetNext(rbusObject_t object, rbusObject_t next);

rbusObjectType_t rbusObject_GetType(rbusObject_t object);

void rbusObject_fwrite(rbusObject_t obj, int depth, FILE* fout);

#ifdef __cplusplus
}
#endif
#endif
/** @} */
