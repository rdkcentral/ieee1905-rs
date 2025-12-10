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
 * @file        rubs_filter.h
 * @brief       rbusFilter
 * @defgroup    rbusFilter
 * @brief       An rbus filter represents a value test placed on an event that must be met before the event is published.
 *
 * The filter contains an expression which evaluates to a boolean result when a test value is applied to it.
 * There are 2 types of filter : relation and logic.  These are tantamount to the relation and logic operators in C/C++.  
 * Relation operator are: >, >=, <, <=, ==, and !=.  Logic operators are: &&, ||, and !.
 * Relation filters are created with rbusFilter_InitRelation and are what an event value is tested with.
 * They are defined with an operator (e.g. >) and a value (e.g. 10) to form an expression such as: (X > 10).
 * Logic filters are created with rbusFilter_InitLogic and are applied on relation filters to AND, OR, or NOT them, 
 * such as ((X > 10) || (X < -10)). Additionally, Logic filters can be applied to other 
 * logic filters to created nested logic such as: ((X > 10) || (X < -10)) || ((X > -5) && (X < 5)).
 * After a filter is created, its expression can be evaluate using a given value (a given X) by calling rbusFilter_Apply.
 * For example, given X=3, the last expression would evaluate to true.
 *
 * @{
 */

#ifndef RBUS_FILTER_H
#define RBUS_FILTER_H

#include "rbus_value.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief       The type of relation operator
 * @enum        rbusFilter_RelationOperator_t
 */
typedef enum
{
    RBUS_FILTER_OPERATOR_GREATER_THAN,
    RBUS_FILTER_OPERATOR_GREATER_THAN_OR_EQUAL,
    RBUS_FILTER_OPERATOR_LESS_THAN,
    RBUS_FILTER_OPERATOR_LESS_THAN_OR_EQUAL,
    RBUS_FILTER_OPERATOR_EQUAL,
    RBUS_FILTER_OPERATOR_NOT_EQUAL
} rbusFilter_RelationOperator_t;

/**
 * @brief       The type of logical operator
 * @enum        rbusFilter_LogicOperator_t
 */
typedef enum
{
    RBUS_FILTER_OPERATOR_AND,
    RBUS_FILTER_OPERATOR_OR,
    RBUS_FILTER_OPERATOR_NOT
} rbusFilter_LogicOperator_t;

/**
 * @brief       The type of expression
 * @enum        rbusFilter_ExpressionType_t
 */
typedef enum
{
    RBUS_FILTER_EXPRESSION_RELATION,
    RBUS_FILTER_EXPRESSION_LOGIC,
} rbusFilter_ExpressionType_t;

/**
 * @brief       A handle to an rbus filter.
 */
typedef struct _rbusFilter* rbusFilter_t;

/** @fn void rbusFilter_InitRelation(
 *          rbusFilter_t* filter,
 *          rbusFilter_RelationOperator_t op,
 *          rbusValue_t value)
 *  @brief  Allocate and initialize a relation filter
 *
 * Create a relation filter from a relation operator and a comparison value.
 * This creates an equation in the form (X op value), where the op and value are supplied
 * with this function, and the X to actually compare against is supplied with rbusFilter_Apply.
 * It's the caller's responsibility to release ownership by calling rbusFilter_Release once it's done with it.
 *  @param  filter      A reference to an address where the new filter will be assigned.
 *                      The caller is responsible for releasing the filter with rbusFilter_Release.
 *  @param  op          The relation operator to use
 *  @param  value       The value to compare against
 */
void rbusFilter_InitRelation(
    rbusFilter_t* filter,
    rbusFilter_RelationOperator_t op,
    rbusValue_t value);

/** @fn void rbusFilter_InitLogic(
 *          rbusFilter_t* filter,
 *          rbusFilter_LogicOperator_t op,
 *          rbusFilter_t left,
 *          rbusFilter_t right)
 *  @brief  Allocate and initialize a logic filter
 *
 * Create a logic filter from a logic operator and 1 or 2 filters to apply the logic operator to.
 * This creates an equation in the form either (left op right) if op is not RBUS_FILTER_OPERATOR_NOT,
 * or !(left) otherwise.  This function allows you to combine both relation and logic filters to create
 * nested expression.  The filter is actually tested against a value using rbusFilter_Apply.
 * It's the caller's responsibility to release ownership by calling rbusFilter_Release once it's done with it.
 *  @param  filter      A reference to an address where the new filter will be assigned.
 *                      The caller is responsible for releasing the filter with rbusFilter_Release.
 *  @param  op          The logic operator to use
 *  @param  left        The left side of the equation
 *                      If op is RBUS_FILTER_OPERATOR_NOT then only the left filter will be notted
 *  @param  right       The right side of the equation
 *                      If op is RBUS_FILTER_OPERATOR_NOT the right should be NULL.
 */
void rbusFilter_InitLogic(
    rbusFilter_t* filter,
    rbusFilter_LogicOperator_t op,
    rbusFilter_t left,
    rbusFilter_t right);

/** @fn void rbusFilter_Retain(rbusFilter_t filter)
 *  @brief Take shared ownership of the filter.  This allows a filter to have 
 *         multiple owners.  The first owner obtains ownership with rbusFilter_Init....
 *         Additional owners can be assigned afterwards with rbusFilter_Retain.  
 *         Each owner must call rbusFilter_Release once done using the filter.
 *  @param filter       The filter to retain
 */
void rbusFilter_Retain(rbusFilter_t filter);

/** @fn void rbusFilter_Release(rbusFilter_t filter)
 *  @brief Release ownership of the value.  This must be called when done using
 *         a filter that was retained with either rbusFilter_Init... or rbusFilter_Retain.
 *  @param filter       The filter to release
 */
void rbusFilter_Release(rbusFilter_t filter);

/** @fn bool rbusFilter_Apply(rbusFilter_t filter, rbusValue_t val)
 *  @brief Apply a filter against a given value.
 *
 * This applies an filter on a given value where the outcome of the filter's
 * full expression will be either a boolean true or false.
 *  @param filter       The filter to test with
 *  @param filter       The value to test
 *  @return             The expression result (true or false)
 */
bool rbusFilter_Apply(rbusFilter_t filter, rbusValue_t value);

/** @name rbusFilter_Get[Member]
 * @brief These functions give access to the internal members of the filter.
 * @param filter        The filter to get a member from.
 * @return              The members value.
 */
///@{
rbusFilter_ExpressionType_t rbusFilter_GetType(rbusFilter_t filter);

rbusFilter_RelationOperator_t rbusFilter_GetRelationOperator(rbusFilter_t filter);

rbusValue_t rbusFilter_GetRelationValue(rbusFilter_t filter);

rbusFilter_LogicOperator_t rbusFilter_GetLogicOperator(rbusFilter_t filter);

rbusFilter_t rbusFilter_GetLogicLeft(rbusFilter_t filter);

rbusFilter_t rbusFilter_GetLogicRight(rbusFilter_t filter);
///@}

/** @fn void rbusFilter_Compare(rbusFilter_t filter1, rbusFilter_t filter2)
 *  @brief Compare two filters for equality.
 *  @param filter1 the first filter to compare
 *  @param filter2 the second filter to compare
 *  @return The compare result where 0 is equal and non-zero if not equal. 
 */
int rbusFilter_Compare(rbusFilter_t filter1, rbusFilter_t filter2);

/** @fn void rbusFilter_fwrite(rbusFilter_t obj, FILE* fout, rbusValue_t value)
 *  @brief A debug utility function to write the filter as a string to a file stream.
 */
void rbusFilter_fwrite(rbusFilter_t filter, FILE* fout, rbusValue_t value);

#ifdef __cplusplus
}
#endif
#endif

/** @} */
