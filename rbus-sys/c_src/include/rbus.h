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
 * @file        rbus.h
 * @brief       rbus.h top level include file.
 *              This is the only file a provider or client needs to include in their project.
 */

/**
 * @mainpage RDK Bus (RBus)
 * RDK Bus (RBus) is a lightweight, fast and efficient bus messaging system. 
 * It allows interprocess communication (IPC) and remote procedure call (RPC)
 * between multiple process running on a hardware device.  It supports the
 * creation and use of a data model, which is a hierarchical tree of named 
 * objects with properties, events, and methods.
 *
 * From a developer perspective, there are providers and clients.
 * Providers implement the data model which clients consume.
 *
 * Providers perform these tasks:
 *  - register properties and implement their get and set operations
 *  - register object and implement their get, set, create, and delete operations
 *  - register and plublish events
 *  - register and implement methods which can be called remotely
 *
 * Consumers perform these tasks:
 *  - get and set property values.
 *  - get, set, create, and delete objects.
 *  - subscribe and listen to events
 *  - invoke remote methods
 *
 * A process can be both a provider and a client.  A process can implement many properties,
 * objects, events, and remote methods, and also be a client of the same coming from other providers.
 *
 * All objects, properties, events, and methods are assigned names by the provider.
 * Each name should be unique across a system, otherwise there will be conflicts in the bus routing.
 *
 * RBus supports the naming convention defined by TR-069, where a name has a hierarchical structure
 * like a file directory structure, with each level of the hierarchy separated by a dot ('.'), and where
 * object instances and denoted using brace({}).
 * 
 * The RBus API is intended, but not limited, to allow the implementation of a TR-181 data model.
 */

/**
 * @defgroup    Common          Common
 * @defgroup    Initialization  Initialization
 * @defgroup    Consumers       Consumers
 * @defgroup    Providers       Providers
 * @defgroup    Tables          Tables
 * @defgroup    Events          Events
 * @defgroup    Methods         Methods
 * @defgroup    Discovery       Discovery
 */

#ifndef RBUS_H
#define RBUS_H

#include <stddef.h>
#include "rbus_value.h"
#include "rbus_property.h"
#include "rbus_object.h"
#include "rbus_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup Common
 *  @{
 */
struct _rbusHandle;

///  @brief     An RBus handle which identifies an opened component
typedef struct _rbusHandle* rbusHandle_t;

///  @brief     The maximum length a name can be for any element.
#define RBUS_MAX_NAME_LENGTH 256

///  @brief     The maximum hierarchical depth (e.g. the max token count) a name can be for any element.
#define RBUS_MAX_NAME_DEPTH 16

///  @brief     All possible error codes this API can generate.
typedef enum _rbusError
{
    //Generic error codes
    RBUS_ERROR_SUCCESS                  = 0,    /**< Succes                   */
    RBUS_ERROR_BUS_ERROR                = 1,    /**< General Error            */
    RBUS_ERROR_INVALID_INPUT,                   /**< Invalid Input            */
    RBUS_ERROR_NOT_INITIALIZED,                 /**< Bus not initialized      */
    RBUS_ERROR_OUT_OF_RESOURCES,                /**< Running out of resources */
    RBUS_ERROR_DESTINATION_NOT_FOUND,           /**< Dest element not found   */
    RBUS_ERROR_DESTINATION_NOT_REACHABLE,       /**< Dest element not reachable*/
    RBUS_ERROR_DESTINATION_RESPONSE_FAILURE,    /**< Dest failed to respond   */
    RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION,/**< Invalid dest response   */
    RBUS_ERROR_INVALID_OPERATION,               /**< Invalid Operation        */
    RBUS_ERROR_INVALID_EVENT,                   /**< Invalid Event            */
    RBUS_ERROR_INVALID_HANDLE,                  /**< Invalid Handle           */
    RBUS_ERROR_SESSION_ALREADY_EXIST,           /**< Session already opened   */
    RBUS_ERROR_COMPONENT_NAME_DUPLICATE,        /**< Comp name already exists */
    RBUS_ERROR_ELEMENT_NAME_DUPLICATE,          /**< One or more element name(s) were previously registered */
    RBUS_ERROR_ELEMENT_NAME_MISSING,            /**< No names were provided in the name field */
    RBUS_ERROR_COMPONENT_DOES_NOT_EXIST,        /**< A bus connection for this component name was not previously opened. */
    RBUS_ERROR_ELEMENT_DOES_NOT_EXIST,          /**< One or more data element name(s) do not currently have a valid registration */
    RBUS_ERROR_ACCESS_NOT_ALLOWED,              /**< Access to the requested data element was not permitted by the provider component. */
    RBUS_ERROR_INVALID_CONTEXT,                 /**< The Context is not same as what was sent in the get callback handler.*/
    RBUS_ERROR_TIMEOUT,                         /**< The operation timedout   */
    RBUS_ERROR_ASYNC_RESPONSE,                  /**< The method request will be handle asynchronously by provider */
    RBUS_ERROR_INVALID_METHOD,                  /**< Invalid Method           */
    RBUS_ERROR_NOSUBSCRIBERS,                   /**< No subscribers present   */
    RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST,      /**< The subscription already exists*/
    RBUS_ERROR_INVALID_NAMESPACE,               /**< Invalid namespace as per standard */
    RBUS_ERROR_DIRECT_CON_NOT_EXIST,            /**< Direct connection not exist */
    RBUS_ERROR_NOT_WRITABLE,                    /**< Set to the requested data element was not permitted by the provider component.*/
    RBUS_ERROR_NOT_READABLE,                    /**< Get to the requested data element was not permitted by the provider component.*/
    RBUS_ERROR_INVALID_PARAMETER_TYPE,          /**< Invalid parameter type.*/
    RBUS_ERROR_INVALID_PARAMETER_VALUE          /**< Invalid parameter value.*/
} rbusError_t;



char const * rbusError_ToString(rbusError_t e);

/** @struct     rbusSetOptions_t
 *  @brief      Additional options a client can pass to a set function.
 *  @ingroup    Common Consumers
 */
typedef struct _rbusSetOptions
{
    bool commit;            /**< Commit flag indicating which set operation is the
                                 last set operation in a particular session.
                                 Set to true to for the final set of a session.
                                 Set to false to for all other sets of a session,
                                 which indicates that the set operation should be remembered
                                 until the final set occurs. */
    uint32_t sessionId;     /**< Session id. One or more parameter can be set together over a session.
                                 The session ID binds all set operations. A value of 0 indicates
                                 this is not a session based operation. A non-zero value indicates that the
                                 value should be "remembered" temporarily. Only when the "commit" parameter
                                 is "true", should all remembered parameters in this session be set together.
                                 Call rbus_createSession to generate a session id.*/
} rbusSetOptions_t;

/** @struct     rbusGetHandlerOptions_t
 *  @brief      Additional options that are passed to the provider when GET function called.
 *  @ingroup    Common Providers
 */
typedef struct _rbusGetHandlerOptions
{
    void* context;                      /**< Context, that can be used for building response; */
    char const* requestingComponent;    /**< Component that invoking the GET method. */
} rbusGetHandlerOptions_t;

/** @struct     rbusSetHandlerOptions_t
 *  @brief      Additional options that are passed to the provider when SET function called.
 *  @ingroup    Common Providers
 */
typedef struct _rbusSetHandlerOptions
{
    bool commit;                        /**< Commit flag indicating which set operation is the
                                             last set operation in a particular session.
                                             Set to true to for the final set of a session.
                                             Set to false to for all other sets of a session,
                                             which indicates that the set operation should be remembered
                                             until the final set occurs. */
    uint32_t sessionId;                 /**< Session id. One or more parameter can be set together over a session.
                                             The session ID binds all set operations. A value of 0 indicates
                                             this is not a session based operation. A non-zero value indicates that the
                                             value should be "remembered" temporarily. Only when the "commit" parameter
                                             is "true", should all remembered parameters in this session be set together.
                                             Call rbus_createSession to generate a session id.*/
    char const* requestingComponent;    /**< Component that invoking the SET method. */
} rbusSetHandlerOptions_t;

struct _rbusMethodAsyncHandle;

///  @brief     An RBus handle used for async method responses
typedef struct _rbusMethodAsyncHandle* rbusMethodAsyncHandle_t;

/** @addtogroup Events
 *  @{
 */
/// @brief rbusEventSubAction_t Actions that can be performed for an event
typedef enum
{
    RBUS_EVENT_ACTION_SUBSCRIBE = 0,
    RBUS_EVENT_ACTION_UNSUBSCRIBE
} rbusEventSubAction_t;

/**
 * @enum        rbusEventType_t
 * @brief       The type of events which can be subscribed to or published
 */
typedef enum
{
    RBUS_EVENT_OBJECT_CREATED,   /**< Notification that an object instance was created in table. */
    RBUS_EVENT_OBJECT_DELETED,   /**< Notification that an object instance was deleted in table. */
    RBUS_EVENT_VALUE_CHANGED,    /**< Notification that a property value was changed. */
    RBUS_EVENT_GENERAL,          /**< Provider defined event.*/
    RBUS_EVENT_INITIAL_VALUE,    /**< Notification of initial value immediately after subscription*/
    RBUS_EVENT_INTERVAL,         /**< For event with interval*/
    RBUS_EVENT_DURATION_COMPLETE /**< For event with duration timeout*/
} rbusEventType_t;

/**
 * @struct      rbusEvent_t
 * @brief       The set of data associated with a published event
 */
typedef struct
{
    char const*     name;       /**< Fully qualified event name */
    rbusEventType_t type;       /**< The type of event */
    rbusObject_t    data;       /**< The data for the event */
} rbusEvent_t;

typedef struct
{
    char const*     name;           /**< Fully qualified event name */
    const void*     rawData;       /**< The raw data for the event */
    unsigned int    rawDataLen;   /**< The raw data length*/
} rbusEventRawData_t;

typedef struct _rbusEventSubscription rbusEventSubscription_t;

/** @fn typedef void (* rbusSubscribeAsyncRespHandler_t)(
 *          rbusHandle_t              handle,
 *          prbusEventSubscription_t  subscription,
 *          rbusError_t error)
 *  @brief A component will receive this API callback when a subscription response is received.
 *  This callback is registered with rbusEvent_SubscribeAsync or rbusEvent_SubscribeExAsync. \n
 *  Used by: Any component that subscribes async for events.
 *  @param rbusHandle     Bus Handle
 *  @param subscription   Subscription data created when the client subscribed
 *                        for the event. This will contain the userData, for example.
 *  @param error          Any error that occured
 *                        success, or any provider error code, or timeout (if retry limit reached)
 *  @return void
 */
typedef void (*rbusSubscribeAsyncRespHandler_t)(
    rbusHandle_t handle, 
    rbusEventSubscription_t* subscription,
    rbusError_t error);

/** @fn typedef void (* rbusEventHandler_t)(
 *          rbusHandle_t              handle,
 *          rbusEvent_t const*        eventData
 *          rbusEventSubscription_t*  subscription)
 *  @brief A component will receive this API callback when an event is received.
 *  This callback is registered with rbusEvent_Subscribe. \n
 *  Used by: Any component that subscribes for events.
 *  @param rbusHandle Bus Handle
 *  @param eventData Event data sent from the publishing component
 *  @param subscription Subscription data created when the client subscribed
        for the event.  This will contain the user_data, for example.
 *  @return void
 */
typedef void (*rbusEventHandler_t)(
    rbusHandle_t                handle,
    rbusEvent_t const*          eventData,
    rbusEventSubscription_t*    subscription
);

typedef void (*rbusEventHandlerRawData_t)(
    rbusHandle_t                handle,
    rbusEventRawData_t const*    eventData,
    rbusEventSubscription_t*    subscription
);

/// @brief rbusEventSubscription_t
typedef struct _rbusEventSubscription
{
    char const*         eventName;  /** Fully qualified event name */
    rbusFilter_t        filter;     /** Optional filter that the client would like 
                                        the sender to apply before sending the event
                                      */
    uint32_t             interval;   /**< Total interval period after which
                                         the event needs to be fired. Should
                                         be in multiples of minInterval
                                      */
    uint32_t            duration;   /** Optional maximum duration in seconds until which
                                        the subscription should be in effect. Beyond this 
                                        duration, the event would be unsubscribed automatically. 
                                        Pass "0" for indefinite event subscription which requires 
                                        the rbusEvent_Unsubscribe API to be called explicitly.
                                      */
    void*               handler;    /** fixme rbusEventHandler_t internal*/
    void*               userData;   /** The userData set when subscribing to the event. */
    rbusHandle_t        handle;     /** Private use only: The rbus handle associated with this subscription */
    rbusSubscribeAsyncRespHandler_t asyncHandler;/** Private use only: The async handler being used for any background subscription retries */
    bool                publishOnSubscribe;
} rbusEventSubscription_t;

/** @} */

/** @addtogroup Tables
 *  @{
 */

/// @brief rbusRowName_t
typedef struct _rbusRowName
{
    char const* name;           /** Fully qualified row name */
    uint32_t instNum;           /** Instance number of the row */
    char const* alias;          /** Alias of the row.  NULL if no alias exists */
    struct _rbusRowName* next;  /** The next row name in this list */
} rbusRowName_t;

/** @} */

/** @fn typedef void (* rbusMethodAsyncRespHandler_t)(
 *          rbusHandle_t handle,
 *          char* methodName
 *          rbusObject_t params)
 *  @brief A component will receive this API callback when the result of 
 *  and asynchronous method invoked with rbusMethod_InvokeAsync is ready.\n
 *  Used by: Any component that calls rbusMethod_InvokeAsync.
 *  @param rbusHandle Bus Handle
 *  @param methodName The method name
 *  @param error      Any error that occured
 *  @param params     The returned params of the method
 *  @return void
 *  @ingroup Methods
 */
typedef void (*rbusMethodAsyncRespHandler_t)(
    rbusHandle_t handle, 
    char const* methodName, 
    rbusError_t error,
    rbusObject_t params
);

/** @addtogroup Providers
  * @{ 
  */

/// @brief rbusElementType_t indicates the type of data elements which can be registered with RBus
typedef enum 
{
    RBUS_ELEMENT_TYPE_PROPERTY = 1,     /**< Property Element. 
                                             Sample names: x.y, p.q.{i}.r, aaa, etc 
                                             Can also be monitored and event 
                                             notifications be obtained in the 
                                             form of events                   */
    RBUS_ELEMENT_TYPE_TABLE,            /**< Table (e.g. multi-instance object)
                                             Sample names: a.b.{i}, a.b.{i}.x.y.{i} */
                                           
    RBUS_ELEMENT_TYPE_EVENT,            /**< (Exclusive) Event Element 
                                             Sample names: a.b.c!, zzzz!      */
                                           
    RBUS_ELEMENT_TYPE_METHOD            /**< Method Element                   
                                             Sample names: m.n.o(), dddddd()  */
} rbusElementType_t;

/** @fn typedef rbusError_t (*rbusGetHandler_t)(
 *          rbusHandle_t handle, 
 *          rbusProperty_t property)
 *  @brief  A property get callback handler.
 *
 * A provider must implement this handler to allow a property to be read.  The
 * property parameter passed to this function will have the name of the property
 * already set.  The provider can use this name to identify the property if needed.
 * The provider's responsibility is to set the value of the property parameter.
 * A provider may install this get handler on a table if the provider doesn't
 * use rbusTable_addRow to add rows and instead will handle partial path queries
 * through this get handler.
 *  @param      handle          the rbus handle the property is registered to.
 *  @param      property        the property whose value must be set by the handler. 
 *  @param      options         the additional information that to be used for GET.
 *  @return                     RBus error code as defined by rbusError_t.
 */
typedef rbusError_t (*rbusGetHandler_t)(
    rbusHandle_t handle, 
    rbusProperty_t property,
    rbusGetHandlerOptions_t* options
);

/** @fn typedef rbusError_t (*rbusSetHandler_t)(
 *          rbusHandle_t handle, 
 *          rbusProperty_t property,
 *          rbusSetHandlerOptions_t* options)
 *  @brief  A property set callback handler.
 *
 * A provider must implement this handler to allow a property to be written.  The
 * property parameter passed to this function will have the name of the property
 * already set.  The provider can use this name to identify the property if needed.
 * The property parameter will also have the value. The rbusSetHandlerOptions_t contains
 * addition information which the provider must use to handle how the write should
 * occur.  It is the provider's responsibility to set its internal representation
 * of that property's value with the value contained within the property parameter.
 *  @param      handle          the rbus handle the property is registered to.
 *  @param      property        the property whose value must be set by the handler. 
 *  @param      options         the additional information that to be used for SET.
 *  @return                     RBus error code as defined by rbusError_t.
 */
typedef rbusError_t (*rbusSetHandler_t)(
    rbusHandle_t handle, 
    rbusProperty_t property, 
    rbusSetHandlerOptions_t* options
);

/** @fn typedef rbusError_t (*rbusTableAddRowHandler_t)(
 *          rbusHandle_t handle,
 *          char const* tableName,
 *          char const* aliasName,
 *          uint32_t* instNum)
 *  @brief A table row add callback handler
 *
 * A provider must implement this handler to allow rows to be added to a table.
 * The tableName parameter will end in "." such as "Device.IP.Interface." 
 * The aliasName parameter can optionally be used to specify a unique name for the row.
 * A new row should be assigned a unique instance number and this number should be
 * returned in the instNum output parameter.  
 *  @param  handle          Bus Handle
 *  @param  tableName       The name of a table (e.g. "Device.IP.Interface.")
 *  @param  aliasName       An optional name for the new row.  Must be unique in the table.  Can be NULL.
 *  @param  instNum         Output parameter where the instance number for the new row is returned
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 */
typedef rbusError_t (*rbusTableAddRowHandler_t)(
    rbusHandle_t handle,
    char const* tableName,
    char const* aliasName,
    uint32_t* instNum);

/** @fn typedef rbusError_t (*rbusTableRemoveRowHandler_t)(
 *          rbusHandle_t handle,
 *          char const* rowName)
 *  @brief A table row remove callback handler
 *
 * A provider must implement this handler to allow rows to be removed from a table.
 * The rowName parameter will be a fully qualified name, specifying either the row's instance
 * number (e.g. "Device.IP.Interface.1") or the row's alias (e.g. "Device.IP.Interface.[lan1]").
 *  @param  handle          Bus Handle
 *  @param  rowName         The name of a table row (e.g. "Device.IP.Interface.1")
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 */
typedef rbusError_t (*rbusTableRemoveRowHandler_t)(
    rbusHandle_t handle,
    char const* rowName);

/** @fn typedef rbusError_t (*rbusMethodHandler_t)(
 *          rbusHandle_t handle, 
 *          char const* methodName, 
 *          rbusObject_t inParams,
 *          rbusObject_t outParams
 *          rbusMethodAsyncHandle_t asyncHandle)
 *  @brief A method invocation callback handler
 *
 * A provider must implement this handler to support methods.  
 * There are two ways to return a response to the method.
 * The first is to set outParams in the handler and return RBUS_ERROR_SUCCESS.
 * The second is to send the response later by storing the asyncHandle,
 * returning RBUS_ERROR_ASYNC_RESPONSE from the handler, and later 
 * calling rbusMethod_SendAsyncResponse, passing the asyncHandle and output params.
 *  @param  handle          Bus Handle
 *  @param  methodName      The name of the method being invoked ( e.g. "Device.Foo.SomeFunc()");
 *  @param  inParams        The input parameters to the functions
 *  @param  outParams       The output/return parameters of the functions
 *  @param  asyncHandle     Handle passed to rbusMethod_SendAsyncResponse
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 */
typedef rbusError_t (*rbusMethodHandler_t)(
    rbusHandle_t handle, 
    char const* methodName, 
    rbusObject_t inParams,
    rbusObject_t outParams,
    rbusMethodAsyncHandle_t asyncHandle);

/** @fn typedef rbusError_t (* rbusEventSubHandler_t)(
 *          rbusHandle_t handle,
 *          rbusEventSubAction_t action,
 *          char const* eventName,
 *          rbusFilter_t filter,
 *          int interval,
 *          bool* autoPublish)
 *  @brief An event subcribe callback handler.
 *
 * A provider will receive this callback when the first client subscribes
 * to an event/filter pair or the last client unsubscribes to an event/filter
 * pair or all subscribers have timed out due to max duration. 
 * Distribution of the event to multiple subscribers will be transparently 
 * handled by the library. 
 *  @param      handle          the rbus handle the event is registered to.
 *  @param      action          whether the event is being subscribed or unsubscribe to.
 *  @param      eventName       the fully qualified event name.
 *  @param      filter          an the filter the subscriber would like the provider to
 *                              use to decide when the event can be sent.  This can be NULL
 *                              if no filter was specified by the client. 
 *  @param      interval        if non-zero, indicates that the event should be publish
 *                              repeatedly every 'interval' seconds.  if a filter is 
 *                              also provided, it would publish only when the filter is triggered
 *  @param      autoPublish     output parameter used to disable the default behaviour
 *                              where rbus automatically publishing events for provider
 *                              data elements. When providers set autoPublish to true
 *                              the value will be checked once per second and the
 *                              maximum event rate is one event per two seconds. If faster
 *                              eventing or real-time eventing is required providers
 *                              can set autoPublish to false and implement a custom
 *                              approach. For fastest response time and to avoid missing
 *                              changes that occur faster than once per second, the
 *                              preferred way is to use a callback triggered from the
 *                              lowest level of code to detect a value change. This
 *                              callback may be invoked by vendor code via a HAL API or
 *                              other method.  This callback can be received by the
 *                              component that provides this event and used to send the
 *                              publish message in real time.
 *  @return                     RBus error code as defined by rbusError_t.
 */
typedef rbusError_t (* rbusEventSubHandler_t)(
    rbusHandle_t handle,
    rbusEventSubAction_t action,
    char const* eventName,
    rbusFilter_t filter,
    int32_t interval,
    bool* autoPublish
);

/** @fn typedef rbusError_t (*rbusTableSyncHandler_t)(
 *          rbusHandle_t handle,
 *          char const* tableName)
 *  @brief A table sync callback handler
 *
 * A provider can implement this handler to allow dynamic tables to synchronize rows.
 * The tableName parameter will be a fully qualified name, specifying table's name
 * (e.g. "Device.IP.Interface.").
 *  @param  handle          Bus Handle
 *  @param  tableName       The name of a table (e.g. "Device.IP.Interface.")
 *  @return RBus error code as defined by rbusError_t.
 */
typedef rbusError_t (*rbusTableSyncHandler_t)(
    rbusHandle_t handle,
    char const* tableName
);

/** @struct rbusElementCallbackTable_t
 *  @brief The list of callback handlers supported by a data element.
 *
 * This table also specifies the possible usage for each data element.
 *
 * For properties, the callbacks can be set to control usage as follows:
 * Callback|Property Usage|Table Usage
 * -|-
 * getHandler|allow read access and value-change events|unused
 * setHandler|allow write access|unused
 * updateTableHandler|unused|all table row add and remove
 * eventSubHandler|allow a provider to know when value-change was subscribed to|allow a provider to know when a table update event is subscribed to
 *
 * If a particular usage is supported, then that callback must be set to a
 * function pointer for the handler. If a particular usage is not supported by
 * the component, the callback shall be set "NULL". On call to registger the
 * data element, the rbus library checks for NULL and substitutes a pointer
 * to an error handler function for all unused features
 */
typedef struct rbusElementCallbackTable_t
{
    rbusGetHandler_t         getHandler;                /**< Get parameters
                                                            handler for the
                                                            named paramter   */
    rbusSetHandler_t         setHandler;                /**< Set parameters
                                                            handler for the
                                                            named parameter  */
    rbusTableAddRowHandler_t tableAddRowHandler;        /**< Add row handler
                                                             to a table*/
    rbusTableRemoveRowHandler_t tableRemoveRowHandler;  /**< Remove a row
                                                             from a table*/
    rbusEventSubHandler_t    eventSubHandler;           /**< Event subscribe
                                                            and unsubscribe
                                                            handler for the
                                                            event name       */
    rbusMethodHandler_t      methodHandler;             /**< Method handler  */
    rbusTableSyncHandler_t   tableSyncHandler;          /** Synchronize dynamic table */
} rbusElementCallbackTable_t;

/**
 * @struct      rbusCallbackTable_t
 * @brief       Backward compatibility version of rbusElementCallbackTable_t
 */
typedef struct rbusCallbackTable_t
{
    rbusGetHandler_t         getHandler;                /**< Get parameters
                                                            handler for the
                                                            named paramter   */
    rbusSetHandler_t         setHandler;                /**< Set parameters
                                                            handler for the
                                                            named parameter  */
    rbusTableAddRowHandler_t tableAddRowHandler;        /**< Add row handler
                                                             to a table*/
    rbusTableRemoveRowHandler_t tableRemoveRowHandler;  /**< Remove a row
                                                             from a table*/
    rbusEventSubHandler_t    eventSubHandler;           /**< Event subscribe
                                                            and unsubscribe
                                                            handler for the
                                                            event name       */
    void*                    methodHandler;             /**< Method handler.
                                                            For table type elements (RBUS_ELEMENT_TYPE_TABLE) method handler
                                                            is used to synchronize table rows of dynamic tables */
} rbusCallbackTable_t;

///  @brief rbusDataElement_t The structure used when registering or
///         unregistering a data element to the bus.
typedef struct
{
    char*      		        name;       /**< Name of an element               */
    rbusElementType_t       type;       /**< Type of an element      */
    rbusCallbackTable_t     cbTable;    /**< Element Handler table. A specific
                                             callback can be NULL, if no usage*/
}rbusDataElement_t;

/** @} */

/**
 * @enum        rbusStatus_t
 * @brief       The type of events which can be subscribed to or published
 */
typedef enum
{
    RBUS_ENABLED = 0,       /**< RBus broker is Enabled and Running */
    RBUS_ENABLE_PENDING,    /**< RBus broker will be Enabled on Reboot */
    RBUS_DISABLE_PENDING,   /**< RBus broker will be Disabled on Reboot */
    RBUS_DISABLED           /**< RBus broker is disabled */
} rbusStatus_t;

typedef enum
{
  RBUS_LOG_DEBUG = 0,
  RBUS_LOG_INFO  = 1,
  RBUS_LOG_WARN  = 2,
  RBUS_LOG_ERROR = 3,
  RBUS_LOG_FATAL = 4
} rbusLogLevel_t;

typedef rbusLogLevel_t rbusLogLevel;

/** @fn typedef void (*rbusLogHandler)(
 *          rbusLogLevel_t level,
 *          const char* file,
 *          int line,
 *          int threadId,
 *          char* message);
 *  @brief  A callback handler to get the log messages to application context
 *
 * A component that wants to handle the logs in its own way must register a callback
 * handler to get the log messages.
 *  @param      level           the log level
 *  @param      file            the file name that it prints
 *  @param      line            the line number in the file.
 *  @param      threadId        the threadId.
 *  @param      messages        the log message the library prints.
 *  @return                     None.
 */
typedef void (*rbusLogHandler)(
    rbusLogLevel_t level,
    const char* file,
    int line,
    int threadId,
    char* message);

/** @} */

/** @addtogroup Consumer
 *  @{
 */

typedef enum
{
        RBUS_ACCESS_GET = 1,
        RBUS_ACCESS_SET = 2,
        RBUS_ACCESS_ADDROW = 4,
        RBUS_ACCESS_REMOVEROW = 8,
        RBUS_ACCESS_SUBSCRIBE = 16,
        RBUS_ACCESS_INVOKE = 32
} rbusAccess_t;

typedef struct _rbusElementInfo
{
    char const* name;               /** Fully qualified element name */
    char const* component;          /** Name of the component providing this element */
    rbusElementType_t type;         /** The type of element */
    uint32_t access;                /** rbusAccess_t flags OR'd*/
    struct _rbusElementInfo* next;  /** The next name in this list */    
} rbusElementInfo_t;

/** @} */
/** @} */

/** @addtogroup Initialization
 *  @{
 */

/** @fn rbusStatus_t rbus_checkStatus(
 *          void)
 *
 *  @brief Components use this API to check whether the rbus is enabled in this device/platform
 *  Used by: Components that uses rbus to register events, tables and parameters.
 *
 *  @return RBus bus/daemon status
 */
rbusStatus_t rbus_checkStatus(
    void);

/** @fn rbusError_t rbus_open(
 *          rbusHandle_t* handle, 
 *          char const* componentName)
 *  @brief  Open a bus connection for a software component.
 *  If multiple components share a software process, the first component that
 *  calls this API will establishes a new socket connection to the bus broker.
 *  All calls to this API will receive a dedicated bus handle for that component.
 *  If a component calls this API more than once, any previous busHandle and all
 *  previous data element registrations will be canceled.                     \n
 *  Note: This API supports a single component per software process and also
 *  supports multiple components that share a software process. In the case of
 *  multiple components that share a software process, each component must call
 *  this API to open a bus connection. Only a single socket connection is opened
 *  per software process but each component within that process receives a
 *  separate busHandle.                                                       \n
 *  Used by:  All RBus components to begin a connection with the bus.
 *  @param      handle          Bus Handle
 *  @param      componentName   the name of the component initializing onto the bus
 *  @return                     RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_BUS_ERROR: Indicates there is some bus error. Try later.
 */
rbusError_t rbus_open(
    rbusHandle_t* handle, 
    char const* componentName);

/** @fn rbusError_t rbus_close(
 *          rbusHandle_t handle)
 *  @brief  Removes a logical bus connection from a component to the bus.     \n
 *  Note: In the case of multiple components that share a software process, the
 *  socket connection remains up until the last component in that software process
 *  closes its bus connection.                                                \n
 *  Used by:  All RBus components (multiple components may share a software process)
 *  @param      handle          Bus Handle
 *  @return                     RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_BUS_ERROR: Indicates there is some bus error. Try later.
 */
rbusError_t rbus_close(
    rbusHandle_t handle);
/** @} */

/**
 * @brief Allows a caller to propogate an OpenTelemetry context from client
 * to server.
 * @param rbus The currently opened rbus handle
 * @param traceParent The traceparent part of the TraceContext in HTTP header format
 * @param traceState The tracestate part of the TraceContext in HTTP header format
 * @note Neither the tracePraent or traceState need to include the name of the HTTP header
 *  only the value.
 *  For example. An example HTTP traceparent may look like
 *    traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
 *  The caller should only supply the actual value. There is no need to include the
 *  "traceparent:" prefix. If the "traceparent:" prefix is also included, it will be
 *  removed.
 * @return
 * @see https://www.w3.org/TR/trace-context/
 */
rbusError_t rbusHandle_SetTraceContextFromString(
    rbusHandle_t  rbus,
    char const*   traceParent,
    char const*   traceState);

rbusError_t rbusHandle_ClearTraceContext(
    rbusHandle_t  rbus);

/**
 * @brief
 * @param rbus The currently opened rbus handle
 * @param traceParent
 * @param traceParentLength
 * @param traceState
 * @param traceStateLength
 * @return
 * @see https://www.w3.org/TR/trace-context/
 */
rbusError_t rbusHandle_GetTraceContextAsString(
    rbusHandle_t  rbus,
    char*         traceParent,
    int           traceParentLength,
    char*         traceState,
    int           traceStateLength);

/** @addtogroup Discovery
 *  @{
 */
/** @fn rbusError_t rbus_discoverComponentName (
 *          rbusHandle_t handle,
 *          int numElements, 
 *          char const** elementNames,
 *          int *numComponents, 
 *          char **componentName)
 *  @brief This allows a component to get a list of components that provide
 *  a set of data elements name(s).  The requesting component provides the
 *  number of data elements and a list of data  elements.  The bus infrastructure
 *  provides the number of components and the component names.                \n
 *  Used by: Client
 *  @param      handle          Bus Handle
 *  @param      numElements     The number (count) of data elements
 *  @param      elementNames    The list of element for which components are to be found
 *  @param      numComponents   Total number of components
 *  @param      componentName   Name of the components discovered
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ELEMENT_DOES_NOT_EXIST: Data Element was not previously registered.
 */
rbusError_t rbus_discoverComponentName(
    rbusHandle_t handle,
    int numElements,
    char const** elementNames,
    int *numComponents,
    char ***componentName);

/** @fn rbusError_t rbus_discoverComponentDataElements(
 *          rbusHandle_t handle,
 *          char const* name,
 *          bool nextLevel,
 *          int *numElements,
 *          char** elementNames)
 *  @brief   This enables a component to get a list of all data elements
 *  provided by a component. The  requesting component provides component name
 *  or all data elements under a "partial path" of an element that ends with
 *  "dot". The bus infrastructure provides the number of data elements and the
 *  data element names array.                                                \n
 *  Used by: Client
 *  @param      handle          Bus Handle
 *  @param      name            Name of the component or partial path of an element name.
 *  @param      nextLevel       Indicates whether to retrieve only the immediate elements
                                (true) or retrieve all elements under the partial path (false).
 *  @param      numElements     Number (count) of data elements that were discovered
 *  @param      elementNames    List of elements discovered
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_COMPONENT_DOES_NOT_EXIST: Component name was not previously registered.
 */
rbusError_t rbus_discoverComponentDataElements(
    rbusHandle_t handle,
    char const* name,
    bool nextLevel,
    int *numElements,
    char*** elementNames);

/** @} */

/** @addtogroup Providers
  * @{ 
  */

/** @fn rbusError_t rbus_regDataElements(
 *          rbusHandle_t handle,
 *          int numDataElements, 
 *          rbusDataElement_t *elements)
 *  @brief  A Component uses this API to register one or more named Data
 *  Elements (i.e., parameters and/or event names) that will be accessible /
 *  subscribable by other components. This also registers the callback functions
 *  associated with each data element using the dataElement structure.        \n
 *  Used by:  All components that provide named parameters and/or events that
 *  may be accessed/subscribed by other component(s)
 *  @param      handle          Bus Handle
 *  @param      numDataElements The number (count) of data elements to register
 *  @param      elements        The list of data elements to register
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ELEMENT_NAME_DUPLICATE: Data Element name already exists
 */
rbusError_t rbus_regDataElements(
    rbusHandle_t handle,
    int numDataElements,
    rbusDataElement_t *elements);

/** @fn rbusError_t rbus_unregDataElements(
 *          rbusHandle_t handle,
 *          int numDataElements,
 *          rbusDataElement_t *elements)
 *  @brief  A Component uses this API to unregister one or more previously
 *  registered Data Elements (i.e., named parameters and/or event names) that
 *  will no longer be accessible / subscribable by other components.          \n
 *  Used by:  All components that provide named parameters and/or events that
 *  may be accessed/subscribed by other component(s)
 *  @param      handle      Bus Handle
 *  @param      numDataElements The number (count) of data elements to unregister
 *  @param      elements        The list of data elements to unregister
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ELEMENT_NAME_MISSING: No data element names provided.
 */
rbusError_t rbus_unregDataElements (
    rbusHandle_t handle,
    int numDataElements,
    rbusDataElement_t *elements);

/** @} */

/** @addtogroup Consumers
  * @{ 
  */

/** @fn rbusError_t rbus_get(
 *          rbusHandle_t handle,
 *          char const* name,
 *          rbusValue_t value)
 *  @brief Get the value of a single parameter.\n
 *  Used by: All components that need to get an individual parameter
 *
 * The consumer should call rbusValue_Release when finished using the returned value.
 *  @param      handle          Bus Handle
 *  @param      name            The name of the parameter to get the value of
 *  @param      value           The returned value of the parameter
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 *  RBUS_ERROR_ELEMENT_DOES_NOT_EXIST: Data Element was not previously registered.
 */
rbusError_t rbus_get(
    rbusHandle_t handle, 
    char const* name,
    rbusValue_t* value);

/** @fn rbusError_t rbus_getExt(
 *          rbusHandle_t handle,
 *          int paramCount,
 *          char** paramNames,
 *          int *numProps,
 *          rbusProperty_t** properties)
 *  @brief Gets one or more parameter value(s) in a single bus operation.
 *  This API also supports wild cards or table entries that provide multiple
 *  param values for a single param input. These options are explained below: \n
 *  Option 1: Single param query:                                             \n
 *      paramCount      : 1                                                   \n
 *      paramNames      : parameter name (single element)                     \n
 *      numValues       : 1                                                   \n
 *      values          : parameter value (caller to free memory)             \n
 *  Option 2: Multi params query:                                             \n
 *      paramCount      : n                                                   \n
 *      paramNames      : Array of parameter names (multi element array)      \n
 *      numValues       : n                                                   \n
 *      values          : Array of parameter values (caller to free memory)   \n
 *  Option 3: Partial path query:                                             \n
 *      paramCount      : 1                                                   \n
 *      paramNames      : Param name path that ends with "." (ex: Device.IP.) \n
 *      numValues       : n                                                   \n
 *      values          : Array of parameter values (caller to free memory)   \n
 *  Option 4: Instance Wild card query:                                       \n
 *      paramCount      : 1                                                   \n
 *      paramNames      : Instance Wild card query is possible for tables.
                          For ex: Device.IP.Interface.*.Status
                          Multi indices wild card query is also supported
                          For ex: Device.IP.Interface.*.IP4Address.*.IPAddress
                          Wildcards can be combined with partial path names
                          For ex: Device.IP.Interface.*. IP4Address.
                          Note: In all cases, the exact query would be routed to
                          provider component and it is the responsibility of
                          the provider component to respond with appropriate
                          response.                                           \n
 *      numValues       : n                                                   \n
 *      values          : Array of parameter values (caller to free memory)   \n
 *  Used by: All components that need to get one or more parameters
 *  @param      handle          Bus Handle
 *  @param      paramCount      The number (count) of input elements (parameters)
 *  @param      paramNames      Input elements (parameters)
 *  @param      numProps        The number (count) of output properties
 *  @param      properties      The output properties where each property holds
 *                              a parameter name and respective value.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 *  RBUS_ERROR_ELEMENT_DOES_NOT_EXIST: Data Element was not previously registered.
 *  RBUS_ERROR_DESTINATION_NOT_REACHABLE: Destination element was not reachable.
 */
rbusError_t rbus_getExt(
    rbusHandle_t handle,
    int paramCount,
    char const** paramNames,
    int *numProps,
    rbusProperty_t* properties);

/** @fn rbusError_t rbus_getBoolean(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          int* paramVal)
 *  @brief A component uses this to perform an boolean get operation.  \n
 *  Used by: All components that need to get an boolean parameter
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the boolean parameter
 *  @param      paramVal        The value of the boolean parameter
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to the requested parameter is not permitted
 */
rbusError_t rbus_getBoolean(
    rbusHandle_t handle,
    char const* paramName,
    bool* paramVal);

/** @fn rbusError_t rbus_getInt(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          int* paramVal)
 *  @brief A component uses this to perform an integer get operation.  \n
 *  Used by: All components that need to get an integer parameter
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the integer parameter
 *  @param      paramVal        The value of the integer parameter
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to the requested parameter is not permitted
 */
rbusError_t rbus_getInt(
    rbusHandle_t handle,
    char const* paramName,
    int* paramVal);

/** @fn rbusError_t rbus_getUint(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          unsigned int* paramVal)
 *  @brief A component uses this to perform a get operation on an
 *  unsigned int parameter. \n
 *  Used by: All components that need to get an unsigned integer parameter
 *  @param      handle      Bus Handle
 *  @param      paramName       The name of the unsigned integer parameter
 *  @param      paramVal        The value of the unsigned integer parameter
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 */
rbusError_t rbus_getUint(
    rbusHandle_t handle,
    char const* paramName,
    unsigned int* paramVal);

/** @fn rbusError_t rbus_getStr(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          char** paramVal)
 *  @brief A component uses this to perform a get operation on a
 *  string parameter. \n
 *  Used by: All components that need to get a string parameter
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the string parameter
 *  @param      paramVal        The value of the string parameter which the caller must free
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 */
rbusError_t rbus_getStr (
    rbusHandle_t handle,
    char const* paramName,
    char** paramVal);

/** @fn rbusError_t rbus_set(
 *          rbusHandle_t handle,
 *          char const* name,
 *          rbusValue_t value,
 *          rbusSetOptions_t* opts)
 *  @brief A component uses this to perform a set operation for a single
 *  explicit parameter and has the option to used delayed (coordinated)
 *  commit commands. \n
 *  Used by: All components that need to set an individual parameter
 *  @param      handle          Bus Handle
 *  @param      name            The name of the parameter to set.
 *  @param      value           The value to set the parameter to.
 *  @param      opts            Extra options such as session info. 
 *                              Set NULL if not needed, in which case a session
 *                              is not used and the set is commited immediately.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted
 */
rbusError_t rbus_set(
    rbusHandle_t handle,
    char const* name,
    rbusValue_t value,
    rbusSetOptions_t* opts);

rbusError_t rbus_setCommit(
    rbusHandle_t handle,
    char const* name,
    rbusSetOptions_t* opts);

/** @fn rbusError_t rbus_setMulti(
 *          rbusHandle_t handle,
 *          int numProps,
 *          rbusProperty_t properties,
 *          rbusSetOptions_t* opts)
 *  @brief A component uses this to perform a set operation for multiple
 *  parameters at once.  \n
 *  Used by: All components that need to set multiple parameters
 *  @param      handle          Bus Handle
 *  @param      numProps        The number (count) of parameters
 *  @param      properties      The list of properties to set the parameters to.
 *                              For each parameter, a property should
 *                              be created which contains the parameter's name and
 *                              the respective value to set that parameter to.
 *  @param      opts            Extra options such as session info. 
 *                              Set NULL if not needed, in which case a session
 *                              is not used and the set is commited immediately.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 *  RBUS_ERROR_DESTINATION_NOT_REACHABLE: Destination element was not reachable.
 */
rbusError_t rbus_setMulti(
    rbusHandle_t handle,
    int numProps,
    rbusProperty_t properties,
    rbusSetOptions_t* opts);

/** @fn rbusError_t rbus_setMultiExt(
 *          rbusHandle_t handle,
 *          uint32_t numProps,
 *          rbusProperty_t properties,
 *          rbusSetOptions_t* opts,
 *          uint32_t timeout,
 *          char** failedParameterName);
 *
 *  @brief A component uses this to perform a set operation for multiple parameters at once.
 *  This method identifies the provider component of each parameter, groups them and makes the SET call \n
 *  per provider component. The given order is NOT maintained.
 *
 *  This API ensures rolling back of all the property to previous value upon failure to set any single parameter in the given list.
 *  Used by: All components that need to set multiple parameters
 *
 *  @param      handle          Bus Handle
 *  @param      numProps        The number (count) of parameters
 *  @param      properties      The list of dml properties to set to. 
 *                              For each parameter, a property should be created which contains the parameter's name and
 *                              the respective value to set that parameter to.
 *  @param      opts            Extra options such as session info. 
 *                              Set NULL if not needed, in which case a session
 *                              is not used and the set is commited immediately.
 *  @param      timeout         Timeout in milliseconds to be used for each SET per provider; Set to 0 to use the default value (15s).
 *  @param      failedParameterName  Output parameter that represents the failed property. On success, it will returning NULL. Caller responsible to free() this.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_INVALID_INPUT: Given inputs are not correct.
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 *  RBUS_ERROR_DESTINATION_NOT_REACHABLE: Destination element was not reachable.
 */
rbusError_t rbus_setMultiExt(
    rbusHandle_t handle,
    uint32_t numProps,
    rbusProperty_t properties,
    rbusSetOptions_t* opts,
    uint32_t timeout,
    char** failedParameterName);

/** @fn rbusError_t rbus_setBoolean(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          bool paramVal)
 *  @brief A component uses this to perform a simple set operation on a
 *  boolean parameter and commit the operation. \n
 *  Used by: All components that need to set a boolean parameter
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the string parameter
 *  @param      paramVal        The value to set the boolean parameter to
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 */
rbusError_t rbus_setBoolean(
    rbusHandle_t handle,
    char const* paramName,
    bool paramVal);

/** @fn rbusError_t rbus_setInt(
 *          rbusHandle_t handle, 
 *          char const* paramName, 
 *          int paramVal)
 *  @brief A component uses this to perform a simple set operation on an
 *  integer parameter and commit the operation. \n
 *  Used by: All components that need to set an integer and commit the change.
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the integer parameter
 *  @param      paramVal        The value to set the integer parameter to
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted
 */
rbusError_t rbus_setInt(
    rbusHandle_t handle, 
    char const* paramName, 
    int paramVal);

/** @fn rbusError_t rbus_setUInt(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          unsigned int paramVal)
 *  @brief A component uses this to perform a simple set operation on an
 *  unsigned integer parameter and commit the operation.  \n
 *  Used by: All components that need to set an unsigned integer and commit
 *  the change.
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the unsigned integer parameter
 *  @param      paramVal        The value to set the unsigned integer parameter to
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 */
rbusError_t rbus_setUInt(
    rbusHandle_t handle,
    char const* paramName,
    unsigned int paramVal);

/** @fn rbusError_t rbus_setStr(
 *          rbusHandle_t handle,
 *          char const* paramName,
 *          char const* paramVal)
 *  @brief A component uses this to perform a simple set operation on a
 *  string parameter and commit the operation. \n
 *  Used by: All components that need to set a string parameter
 *  @param      handle          Bus Handle
 *  @param      paramName       The name of the string parameter
 *  @param      paramVal        The value to set the string parameter to
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are:
 *  RBUS_ERROR_ACCESS_NOT_ALLOWED: Access to requested parameter is not permitted.
 */
rbusError_t rbus_setStr(
    rbusHandle_t handle,
    char const* paramName,
    char const* paramVal);

/** @fn rbusError_t rbusTable_addRow(
 *          busHandle handle, 
 *          char const* tableName,
 *          char const* aliasName,
 *          uint32_t* instNum)
 *  @brief Add a new row to a table
 *
 * This API adds a new row to a table. The tableName parameter must end in ".", 
 * such as "Device.IP.Interface." The aliasName parameter can optionally be used to 
 * specify a unique name for the row.  Any additional properties on the row must be 
 * updated separately using set operations.  Each new row gets a unique instance number
 * assigned to it and this is returned in the instNum output parameter.  Consumers can
 * use either the optionally set aliasName or the returned instNum to identify the new row.
 * Used by:  Any component that needs to add a table rows in another component.
 *  @param  handle          Bus Handle
 *  @param  tableName       The name of a table (e.g. "Device.IP.Interface.")
 *  @param  aliasName       An optional name for the new row.  Must be unique in the table.  Can be NULL.
 *  @param  instNum         Output parameter where the instance number for the new row is returned
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 *  @ingroup Tables
 */

rbusError_t rbusTable_addRow(
    rbusHandle_t handle,
    char const* tableName,
    char const* aliasName,
    uint32_t* instNum);

/** @fn rbusError_t rbusTable_removeRow(
 *          busHandle handle, 
 *          char const* rowName)
 *  @brief Remove a row from a table
 *
 * This API removes a row from a table. The rowName parameter must be a fully qualified
 * name, specifying either the row's instance number (e.g. "Device.IP.Interface.1")
 * or the row's alias (e.g. "Device.IP.Interface.[lan1]").
 * Used by:  Any component that needs to add a table rows in another component.
 *  @param  handle          Bus Handle
 *  @param  rowName         The name of a table row (e.g. "Device.IP.Interface.1")
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 *  @ingroup Tables
 */
rbusError_t rbusTable_removeRow(
    rbusHandle_t handle,
    char const* rowName); 

/** @fn rbusError_t rbusTable_getRowNames(
 *          busHandle handle, 
 *          char const* tableName,
 *          rbusRowName_t** rowNames)
 *  @brief Get a list of the row names in a table
 *
 * This method allows a consumer to get the names of all rows on a table.
 * Used by:  Any component that needs to know the rows in a table.
 *  @param  handle          Bus Handle
 *  @param  tableName       The name of a table (e.g. "Device.IP.Interface.")
 *  @param  rowNames        Output parameter where a list of rbusRowName_t structures is returned
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 *  @ingroup Tables
 */
rbusError_t rbusTable_getRowNames(
    rbusHandle_t handle,
    char const* tableName,
    rbusRowName_t** rowNames);

/** @fn rbusError_t rbusTable_FreeRowNames(
 *          rbusHandle handle, 
 *          rbusRowName_t* rows)
 *  @brief Free the row name list returned from rbusTable_getRowNames
 *
 * This method is used to free the memory for the row name lists returned from rbusTable_getRowNames.
 * Used by:  Any component that uses the busTable_getRowNames method
 *  @param  handle          Bus Handle
 *  @param  rows            The row name list returned from rbusTable_getRowNames
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 *  @ingroup Tables
 */
rbusError_t rbusTable_freeRowNames(
    rbusHandle_t handle, 
    rbusRowName_t* rows);

/** @fn rbusError_t rbusElementInfo_get(
 *          busHandle handle, 
 *          char const* elemName,
 *          int depth,
 *          rbusElementInfo_t** elemInfo);
 *  @brief Get a info on the elements at or inside the give
 *
 * This method allows a consumer to get the information on all elements inside an object.  
  * Used by:  Any component that needs to know the info on the elements inside an object.
 *  @param  handle          Bus Handle
 *  @param  elemName        The name of the element to start from
 *  @param  depth           Depth control flag
 *                              depth = 0: only the start element
 *                              depth = RBUS_MAX_NAME_DEPTH: the start element, its children, grand-children, ... to max depth
 *                              depth > 0: the start element, its children, grand-children, ... to the given depth
 *                              depth < 0: only the elements at the exact depth level of abs(depth)  (e.g. -1 would return only the next level elements)
 *  @param  elemInfo        Output element info list
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 */
rbusError_t rbusElementInfo_get(
    rbusHandle_t handle,
    char const* elemName,
    int depth,
    rbusElementInfo_t** elemInfo);

/** @fn rbusError_t rbusElementInfo_free(
 *          busHandle handle, 
 *          busElementInfo_t* elemInfo);
 *  @brief Free the list element info list returned from rbusElementInfo_get
 *
 * This method allows a consumer to free the element info list returned from the rbusElementInfo_get method.
 * Used by:  Any component that uses the rbusElementInfo_get method
 *  @param  handle          Bus Handle
 *  @param  elemInfoList    The element info list return from rbusElementInfo_get
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 */
rbusError_t rbusElementInfo_free(
    rbusHandle_t handle, 
    rbusElementInfo_t* elemInfo);

/** @} */

/** @addtogroup Providers
  * @{ 
  */

/** @fn rbusError_t rbusTable_registerRow(
 *          busHandle handle, 
 *          char const* tableName,
  *         uint32_t instNum,
  *         char const* aliasName)
 *  @brief Register a row that the provider has added to its own table.
 *
 * This method allows a provider to register a row that it adds to its own table.
 * A provider can add a row internally without the need to call rbusTable_addRow which would
 * call the provider's tableAddRow handler.  However, in order for consumers to know the row exists,
 * it must be registered.
 * Used by:  Any provider that adds a row to its own table.
 *  @param  handle          Bus Handle
 *  @param  tableName       The name of a table (e.g. "Device.IP.Interface.")
 *  @param  instNum         The unique instance number the provider has assigned this row.
 *  @param  aliasName       An optional name for the new row.  Must be unique in the table.  Can be NULL.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 *  @ingroup Tables
 */
rbusError_t rbusTable_registerRow(
    rbusHandle_t handle,
    char const* tableName,
    uint32_t instNum,
    char const* aliasName);

/** @fn rbusError_t rbusTable_unregisterRow(
 *          busHandle handle, 
 *          char const* rowName)
 *  @brief Unregister a row that the provider has removed from its own table.
 *
 * The method allows a provider to unregister a row that it removes from its own table.
 * A provider can remove a row internally without the need to call rbusTable_removeRow which would
 * call the provider's tableRemoveRow handler.  However, in order for consumer to know the row no
 * longer exists, it must be unregistered.
 * Used by:  Any provider that removes a row from its own table.
 *  @param  handle          Bus Handle
 *  @param  rowName         The name of a table row (e.g. "Device.IP.Interface.1")
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_INPUT
 *  @ingroup Tables
 */

rbusError_t rbusTable_unregisterRow(
    rbusHandle_t handle,
    char const* rowName);

/** @} */

/** @addtogroup Consumers
  * @{ 
  */

/** @fn bool rbusEvent_IsSubscriptionExist(
 *          rbusHandle_t        handle,
 *          char const*         eventName,
 *          rbusEventSubscription_t*    subscription)
 *  @brief Find active subscription given eventName with subscription structure.
 *  Used by: Components that need to find whether they have active subscription
 *  already or not for the given eventName with subscription structure.
 *  The eventName should be a name which was previously subscribed
 *  @param      handle          Bus Handle
 *  @param      eventName       The fully qualified name of the event
 *  @param      subscription    The subscription which was previously subscribed
 *  @return     true or false
 *  @ingroup Events
 */
bool  rbusEvent_IsSubscriptionExist(
    rbusHandle_t        handle,
    char const*         eventName,
    rbusEventSubscription_t*    subscription);

/** @fn rbusError_t  rbusEvent_Subscribe(
 *          rbusHandle_t        handle,
 *          char const*         eventName,
 *          rbusEventHandler_t  handler,
 *          void*               userData,
 *          int                 timeout)
 *  @brief Subscribe to a single event.  \n
 *  Used by: Components that need to subscribe to an event.
 * The handler will be called back when the event is generated. 
 * The type of event and when the event is generated is based 
 * on the type of data element eventName refers to.
 * If eventName is the name of a general event, the event is 
 * generated when the provider of the event, publishes it.
 * If eventName is the name of a parameter, the event is 
 * generated when the value of that parameter changes.
 * If eventName is the name of a table, the event is generated
 * when a row is added or deleted from that table.
 * If timeout is positive, internal retries will be attempted if the subscription
 * cannot be routed to an existing provider, and the retries will continue until
 * either a provider is found, an unrecoverable error occurs, or retry timeout reached.
 * A component should call rbusEvent_Unsubscribe to stop receiving the event.
 *  @param      handle          Bus Handle
 *  @param      eventName       The fully qualified name of the event
 *  @param      handler         The event callback handler
 *  @param      userData        User data to be passed back to the callback handler
 *  @param      timeout         Max time in seconds to attempt retrying subscribe
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t  rbusEvent_Subscribe(
    rbusHandle_t        handle,
    char const*         eventName,
    rbusEventHandler_t  handler,
    void*               userData,
    int                 timeout);

/** @fn rbusError_t  rbusEvent_SubscribeRawData(
 *          rbusHandle_t        handle,
 *          char const*         eventName,
 *          rbusEventHandler_t  handler,
 *          void*               userData,
 *          int                 timeout)
 *  @brief Subscribe to a single event using rawdata method, with reduced memory and 
 *  cpu footprint.
 *  Used by: Components that need to subscribe to an event.
 * The handler will be called back when the event is generated. 
 * If timeout is positive, internal retries will be attempted if the subscription
 * cannot be routed to an existing provider, and the retries will continue until
 * either a provider is found, an unrecoverable error occurs, or retry timeout reached.
 * A component should call rbusEvent_UnsubscribeRawData to stop receiving the event.
 *  @param      handle          Bus Handle
 *  @param      eventName       The fully qualified name of the event
 *  @param      handler         The event callback handler
 *  @param      userData        User data to be passed back to the callback handler
 *  @param      timeout         Max time in seconds to attempt retrying subscribe
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t  rbusEvent_SubscribeRawData(
    rbusHandle_t        handle,
    char const*         eventName,
    rbusEventHandler_t  handler,
    void*               userData,
    int                 timeout);

/** @fn rbusError_t  rbusEvent_SubscribeAsync(
 *          rbusHandle_t                    handle,
 *          char const*                     eventName,
 *          rbusEventHandler_t              handler,
 *          rbusSubscribeAsyncRespHandler_t subscribeHandler,
 *          void*                           userData,
 *          int                             timeout)
 *  @brief Subscribe asynchronously to a single event.  \n
 *  Used by: Components that need to subscribe asynchronously to an event.
 * The handler will be called back when the event is generated. 
 * The type of event and when the event is generated is based 
 * on the type of data element eventName refers to.
 * If eventName is the name of a general event, the event is 
 * generated when the provider of the event, publishes it.
 * If eventName is the name of a parameter, the event is 
 * generated when the value of that parameter changes.
 * If eventName is the name of a table, the event is generated
 * when a row is added or deleted from that table.
 * The subscribeHandler is called when either a provider responds to the 
 * subscription request, an unrecoverable error occurs, or retry timeout reached.
 * If timeout is positive, internal retries will be attempted if the subscription 
 * cannot be routed to an existing provider, and the retries will continue until 
 * either a provider is found, an unrecoverable error occurs, or retry timeout reached.
 * A component should call rbusEvent_Unsubscribe to stop receiving the event.
 *  @param      handle            Bus Handle
 *  @param      eventName         The fully qualified name of the event
 *  @param      handler           The event callback handler
 *  @param      subscribeHandler  The subscribe callback handler
 *  @param      userData          User data to be passed back to the callback handler
 *  @param      timeout           Max time in seconds to attempt retrying subscribe
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t  rbusEvent_SubscribeAsync(
    rbusHandle_t                    handle,
    char const*                     eventName,
    rbusEventHandler_t              handler,
    rbusSubscribeAsyncRespHandler_t subscribeHandler,
    void*                           userData,
    int                             timeout);

/** @fn rbusError_t  rbusEvent_Unsubscribe(
 *          rbusHandle_t        handle,
 *          char const*         eventName)
 *  @brief Unsubscribe from a single event.  \n
 *  Used by: Components that need to unsubscribe from an event.
 *
 * The eventName should be a name which was previously subscribed 
 * to with either rbusEvent_Subscribe or rbusEvent_SubscribeEx.
 *  @param      handle          Bus Handle
 *  @param      eventName       The fully qualified name of the event.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t rbusEvent_Unsubscribe(
    rbusHandle_t        handle,
    char const*         eventName);

/** @fn rbusError_t  rbusEvent_UnsubscribeRawData(
 *          rbusHandle_t        handle,
 *          char const*         eventName)
 *  @brief Unsubscribe from a single event.  \n
 *  Used by: Components that need to unsubscribe from an event subscribed using
 *  rbusEvent_SubscribeRawData.
 *
 * The eventName should be a name which was previously subscribed 
 * to with either rbusEvent_Subscribe or rbusEvent_SubscribeEx.
 *  @param      handle          Bus Handle
 *  @param      eventName       The fully qualified name of the event.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */

rbusError_t rbusEvent_UnsubscribeRawData(
    rbusHandle_t        handle,
    char const*         eventName);

/** @fn rbusError_t  rbusEvent_SubscribeEx (
 *          rbusHandle_t handle,
 *          rbusEventSubscription_t* subscription,
 *          int numSubscriptions,
 *          int timeout)
 *  @brief  Subscribe to one or more events with the option to add extra attributes
 *          to each subscription through the rbusEventSubscription_t structure\n
 *  Used by: Components that need to subscribe to events.
 * For each rbusEventSubscription_t subscription, the eventName and handler 
 * are required to be set.  Other options may be set to NULL or 0 if not needed.
 * Subscribing to all items in the subscription array is transactional.  
 * That is, all must succeed to subscribe or none will be subscribed.
 * If timeout is positive, internal retries will be attempted if the subscription
 * cannot be routed to an existing provider, and the retries will continue until
 * either a provider is found, an unrecoverable error occurs, or retry timeout reached.
 *  @param      handle            Bus Handle
 *  @param      subscription      The array of subscriptions to register to
 *  @param      numSubscriptions  The number of subscriptions to register to
 *  @param      timeout           Max time in seconds to attempt retrying subscribe
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t rbusEvent_SubscribeEx(
    rbusHandle_t              handle,
    rbusEventSubscription_t*  subscription,
    int                       numSubscriptions,
    int                       timeout);

/** @fn rbusError_t  rbusEvent_SubscribeExRawData (
 *          rbusHandle_t handle,
 *          rbusEventSubscription_t* subscription,
 *          int numSubscriptions,
 *          int timeout)
 *  @brief  Subscribe to one or more events with the option to add extra attributes
 *          to each subscription through the rbusEventSubscription_t structure\n
 *  Used by: Components that need to subscribe to events using rawdata method, with 
 *  reduced memory and cpu footprint.
 * For each rbusEventSubscription_t subscription, the eventName and handler 
 * are required to be set.  Other options may be set to NULL or 0 if not needed.
 * Subscribing to all items in the subscription array is transactional.  
 * That is, all must succeed to subscribe or none will be subscribed.
 * If timeout is positive, internal retries will be attempted if the subscription
 * cannot be routed to an existing provider, and the retries will continue until
 * either a provider is found, an unrecoverable error occurs, or retry timeout reached.
 *  @param      handle            Bus Handle
 *  @param      subscription      The array of subscriptions to register to
 *  @param      numSubscriptions  The number of subscriptions to register to
 *  @param      timeout           Max time in seconds to attempt retrying subscribe
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t rbusEvent_SubscribeExRawData(
    rbusHandle_t              handle,
    rbusEventSubscription_t*  subscription,
    int                       numSubscriptions,
    int                       timeout);

/** @fn rbusError_t  rbusEvent_SubscribeExAsync (
 *          rbusHandle_t handle,
 *          rbusEventSubscription_t* subscription,
 *          int numSubscriptions,
 *          rbusSubscribeAsyncRespHandler_t subscribeHandler,
 *          int timeout)
 *  @brief  Subscribe asynchronously to one or more events with the option to add extra
 *          attributes to each subscription through the rbusEventSubscription_t structure\n
 *  Used by: Components that need to subscribe asynchronously to events.
 * For each rbusEventSubscription_t subscription, the eventName and handler 
 * are required to be set.  Other options may be set to NULL or 0 if not needed.
 * Subscribing to all items in the subscription array is transactional.  
 * That is, all must succeed to subscribe or none will be subscribed.
 * The subscribeHandler is called after either all subscriptions were successfully 
 * made to providers, any one subscriptions received an error response from a provider, 
 * an unrecoverable error occurs, or retry timeout reached.
 * If timeout is positive, internal retries will be attempted for each subscription that
 * cannot be routed to an existing provider, and the retries will continue until 
 * either a provider is found, an unrecoverable error occurs, or retry timeout reached.
 *  @param      handle            Bus Handle
 *  @param      subscription      The array of subscriptions to register to
 *  @param      numSubscriptions  The number of subscriptions to register to
 *  @param      subscribeHandler  The subscribe callback handler
 *  @param      timeout           Max time in seconds to attempt retrying subscribe
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t rbusEvent_SubscribeExAsync(
    rbusHandle_t                    handle,
    rbusEventSubscription_t*        subscription,
    int                             numSubscriptions,
    rbusSubscribeAsyncRespHandler_t subscribeHandler,
    int                             timeout);

/** @fn rbusError_t  rbusEvent_UnsubscribeEx(
 *          rbusHandle_t handle, 
 *          rbusEventSubscription_t* subscriptions,
 *          int numSubscriptions)
 *  @brief  Unsubscribe from one or more events\n
 *          Used by: Components that need to unsubscribe from events.
 * For each rbusEventSubscription_t subscription, the eventName is required to be set.
 * Other options may be set NULL or 0.
 * The subscriptions pointer can be the same as that passed to rbusEvent_SubscribeEx, or it
 * can be a different list; however, the eventName for each subsription must be one 
 * previously subscribed to with either rbusEvent_Subscribe or rbusEvent_SubscribeEx.
 *  @param      handle          Bus Handle
 *  @param      subscriptions   The array of subscriptions to unregister from
 *  @param      numSubscriptions The number of subscriptions to unregister from
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t rbusEvent_UnsubscribeEx(
    rbusHandle_t handle,
    rbusEventSubscription_t* subscriptions,
    int numSubscriptions);

/** @fn rbusError_t  rbusEvent_UnsubscribeExRawData(
 *          rbusHandle_t handle, 
 *          rbusEventSubscription_t* subscriptions,
 *          int numSubscriptions)
 *  @brief  Unsubscribe from one or more events\n
 *          Used by: Components that need to unsubscribe from events subscribed with 
 * rawdata method.
 * For each rbusEventSubscription_t subscription, the eventName is required to be set.
 * Other options may be set NULL or 0.
 * The subscriptions pointer can be the same as that passed to rbusEvent_SubscribeEx, or it
 * can be a different list; however, the eventName for each subsription must be one 
 * previously subscribed to with either rbusEvent_Subscribe or rbusEvent_SubscribeEx.
 *  @param      handle          Bus Handle
 *  @param      subscriptions   The array of subscriptions to unregister from
 *  @param      numSubscriptions The number of subscriptions to unregister from
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t rbusEvent_UnsubscribeExRawData(
    rbusHandle_t                handle,
    rbusEventSubscription_t*    subscription,
    int                         numSubscriptions);

/** @} */

/** @addtogroup Providers
  * @{ 
  */

/** @fn rbusError_t  rbusEvent_Publish (
 *          rbusHandle_t handle,
 *          rbusEvent_t* eventData)
 *  @brief Publish an event.
 *  
 *  Publishes an event which will be sent to all subscribers of this event. 
 *  This library keeps state of all event subscriptions and duplicates event
 *  messages as needed for distribution. \n
 *  Used by: Components that provide events
 *  @param      handle          Bus Handle
 *  @param      eventData       The event data. 
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t  rbusEvent_Publish(
    rbusHandle_t handle,
    rbusEvent_t* eventData);

/** @fn rbusError_t  rbusEvent_PublishRawData (
 *          rbusHandle_t handle,
 *          rbusEvent_t* eventData)
 *  @brief Publish an event.
 *  
 *  Publishes an event which will be sent to all subscribers of this event. 
 *  This library keeps state of all event subscriptions and duplicates event
 *  messages as needed for distribution. \n
 *  Used by: Components that provide events and want to publish with reduced
 *  memory and cpu footprints
 *  @param      handle          Bus Handle
 *  @param      eventData       The event data. 
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Events
 */
rbusError_t  rbusEvent_PublishRawData(
  rbusHandle_t          handle,
  rbusEventRawData_t*    eventData);

/** @} */

/** @addtogroup Consumers
  * @{ 
  */

/** @fn rbusError_t rbusMethod_Invoke(
 *          rbusHandle_t handle, 
 *          char const* methodName, 
 *          rbusObject_t inParams, 
 *          rbusObject_t* outParams)
 *  @brief Invoke a remote method.
 *  
 *  Invokes a remote method and blocks waiting for the result.
 *  @param      handle      Bus Handle
 *  @param      methodName  Method name
 *  @param      inParams    Input params
 *  @param      outParams   Return params and error response values
 *                          outparams is generated and contains the return value of error rbusError_t
                            On success, it contains method specific data on the outParams.
                            On failure, it contains method specific error code and error description on the outParams.
                            "error_code" & "error_string"
                            provider is responsible in sending the errorcode and error string.
                            other error like no method/handling issues, internal err
                            will be taken care by rbus.
                            consumer side errors returning (RBUS_ERROR_INVALID_HANDLE and RBUS_ERROR_INVALID_INPUT) will not contain outparams for input validation.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_SUCCESS, RBUS_ERROR_BUS_ERROR, RBUS_ERROR_INVALID_INPUT, RBUS_ERROR_TIMEOUT, RBUS_ERROR_INVALID_METHOD, RBUS_ERROR_INVALID_HANDLE
 *  @ingroup Methods
 */
rbusError_t rbusMethod_Invoke(
    rbusHandle_t handle, 
    char const* methodName, 
    rbusObject_t inParams, 
    rbusObject_t* outParams);

/** @fn rbusError_t rbusMethod_InvokeAsync(
 *          rbusHandle_t handle, 
 *          char* methodName, 
 *          rbusObject_t inParams, 
 *          rbusMethodAsyncRespHandler_t callback, 
 *          int timeout)
 *  @brief Invokes a remote method, non-blocking, with an asynchronous return callback.
 *  
 *  Invokes a remote method without blocking.  
 * The return params of the method will be received asynchronously by the callback provided.
 * inParams will be retained and used to invoke the method on a background thread; therefore,
 * inParams should not be altered by the calling program until the callback complete.
 *  @param      handle      Bus Handle
 *  @param      methodName  Method name
 *  @param      inParams    Input params
 *  @param      callback    Callback handler for the method's return parameters.
 *  @param      timeout     Optional maximum time in seconds to receive a callback.
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_INVALID_EVENT
 *  @ingroup Methods
 */
rbusError_t rbusMethod_InvokeAsync(
    rbusHandle_t handle, 
    char const* methodName, 
    rbusObject_t inParams, 
    rbusMethodAsyncRespHandler_t callback, 
    int timeout);

/** @} */

/** @addtogroup Providers
  * @{ 
  */

/** @fn rbusError_t rbusMethod_SendAsyncResponse(
 *          rbusMethodAsyncHandle_t asyncHandle, 
 *          rbusError_t error, 
 *          rbusObject_t outParams)
 *  @brief Send the response to an invoked method.
 *  
 * Providers can use this method to send the result of an invoke method asynchronously.  
 * The asyncHandle is provided when the provider's MethodHandler is called.  
 * The outParams param should be initialized and released by the provider.  outParams can be NULL.
 * The error params should be set to RBUS_ERROR_SUCCESS if the method was successful, 
 * or to an approprioate error if the method fails.  
 *  @param      asyncHandle     Async handle
 *  @param      error           Any error that occured
 *  @param      outParams       The returned params of the method
 *  @return RBus error code as defined by rbusError_t.
 *  @ingroup Methods
 */
rbusError_t rbusMethod_SendAsyncResponse(
    rbusMethodAsyncHandle_t asyncHandle,
    rbusError_t error,
    rbusObject_t outParams);

/** @} */

/** @addtogroup Consumers
  * @{ 
  */

/** @fn rbusError_t rbus_createSession(
 *          rbusHandle_t handle,
 *          uint32_t *pSessionId)
 *
 *  @brief Components use this API to create a new session to set 1 or more parameters
 *      and action on table like add/remove rows. \n
 *  Used by: Components that needs to Set Param & Update Tables.
 *
 *  @param handle Bus Handle
 *  @param pSessionId unique session identified
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_SESSION_ALREADY_EXIST;
 *  @ingroup Events
 */
rbusError_t rbus_createSession(
    rbusHandle_t handle,
    uint32_t *pSessionId);

/** @fn rbusError_t rbus_getCurrentSessionId(
 *          rbusHandle_t handle,
 *          uint32_t *pSessionId)
 *
 *  @brief Components use this API to get the current session to set 1 or more parameters
 *      and action on table like add/remove rows. \n
 *  Used by: Components that needs to Set Param & Update Tables.
 *
 *  @param handle Bus Handle
 *  @param pSessionId return pointer to hold unique session currently in use
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_BUS_ERROR;
 */
rbusError_t rbus_getCurrentSession(
    rbusHandle_t handle,
    uint32_t *pSessionId);

/** @fn rbusError_t rbus_closeSession(
 *          rbusHandle_t handle,
 *          uint32_t sessionId)
 *
 *  @brief Components use this API to close the current session that was used to set 1 or more parameters
 *      and action on table like add/remove rows. \n
 *  Used by: Components that used the session for Set Param & Update Tables.
 *
 *  @param handle Bus Handle
 *  @param sessionId unique session Identifier that is currently in use
 *  @return RBus error code as defined by rbusError_t.
 *  Possible values are: RBUS_ERROR_BUS_ERROR;
 */
rbusError_t rbus_closeSession(
    rbusHandle_t handle,
    uint32_t sessionId);

/** @fn rbusError_t rbus_registerLogHandler(
 *          rbusLogHandler logHandler)
 *
 *  @brief  A callback handler to get the log messages to application context
 *
 *  Used by: Component that wants to handle the logs in its own way must register a callback handler to get the log messages.
 *
 *  @param logHandler   handler function pointer
 *  @return RBus error code as defined by rbusError_t.
 */
rbusError_t rbus_registerLogHandler(
    rbusLogHandler logHandler);

/** @fn rbusError_t rbus_setLogLevel(
 *          rbusLogLevel_t level)
 *
 *  @brief  Component use this API to set the log level to be printed
 *
 *  Used by: Component that wants to use default logging of RBUS instead of overriding the logging, can set the log level by this.
 *
 *  @param level        Log level
 *  @return RBus error code as defined by rbusError_t.
 */

rbusError_t rbus_setLogLevel(rbusLogLevel_t level);

/** @fn rbusError_t rbus_openDirect(
 *          rbusHandle_t handle,
 *          rbusHandle_t* myDirectHandle,
 *          char const* parameterName)
 *
 *  @brief  Component use this API to open direct connection to the provider
 *
 *  Rbus supports a mode that optimizes performance for very frequent, high data rate transfers or rbus operations that need extremely low latency.
 *  This is known as rbus_direct mode.   While this mode improves performance, reduces CPU usage and improves latency, it also uses more memory and
 *  resources compared with normal rbus operation.   Rbus_direct mode should only be used where it's needed and avoided where its not needed.
 *  Developers should use normal rbus operation modes unless there are special circumstances that require rbus_direct mode.  Developers should 
 *  NOT use rbus_direct mode for all operations.   For more information on rbus_direct see the instructions for rbus_openDirect() in rbus.h.
 *
 *  Used by: Component that wants to use private connection to provider and avoid RBUS Daemon.
 *
 *  @param handle           Current active rbus handle
 *  @param myDirectHandle   Direct handle that is created
 *  @param parameterName    Direct connection for the given parameter
 *  @return RBus error code as defined by rbusError_t.
 */
rbusError_t rbus_openDirect(rbusHandle_t handle, rbusHandle_t* myDirectHandle, char const* parameterName);

/** @fn rbusError_t rbus_closeDirect(
 *          rbusHandle_t myDirectHandle)
 *
 *  @brief  Component use this API to close existing direct connection to the provider for the given DML
 *
 *  Used by: Component that is no more need the direct connection and wants to switch to RBUS Daemon
 *
 *  @param myDirectHandle   Direct handle that is created
 *  @return RBus error code as defined by rbusError_t.
 */
rbusError_t rbus_closeDirect(rbusHandle_t handle);

/** @fn rbusError_t rbus_registerDynamicTableSyncHandler(
 *          rbusHandle_t handle,
 *          char const* tableName,
 *          rbusTableSyncHandler_t syncHandler)
 *
 *  @brief  Register tableSyncHandler for table element with dynamic rows.
 *
 *  Used by: Component that wants to register tableSyncHandler that will register/unregister rows of dynamic table.
 *
 *  @param handle         Bus Handle
 *  @param tableName      The name of a table (e.g. "Device.IP.Interface.")
 *  @param syncHandler    Dymanic table sync callback 
 *  @return RBus error code as defined by rbusError_t.
 */
rbusError_t rbus_registerDynamicTableSyncHandler(
    rbusHandle_t handle,
    char const* tableName,
    rbusTableSyncHandler_t syncHandler);

typedef struct _rbusTimeoutValues
{
    uint32_t setTimeout;         /* default timeout in miliseconds for SET API*/
    uint32_t getTimeout;         /* default timeout in miliseconds for GET API*/
    uint32_t setMultiTimeout;    /* default timeout in miliseconds for SET Multi API*/
    uint32_t getMultiTimeout;    /* default timeout in miliseconds for Wildcard Query GET API*/
    uint32_t subscribeTimeout;   /* default timeout in miliseconds for Subscribe operation*/
}rbusTimeoutValues_t;

/** @fn rbusError_t rbusHandle_ConfigTimeoutValues(
 *     rbusHandle_t handle,
 *     rbusTimeoutValues_t timeoutValues);
 *
 *  @brief  Configure timeout values for each rbus_handle.
 *
 *  Used by: Component wants to configure its own timeout values per rbus_handle.
 *
 *  @param handle               Bus Handle
 *  @param timeoutValues        Timeout values in miliseconds for SET, GET operations.
 *  @return RBus error code as defined by rbusError_t.
 */

rbusError_t rbusHandle_ConfigTimeoutValues(rbusHandle_t handle, rbusTimeoutValues_t timeoutValues);

/** @fn int rbusHandle_ConfigSetTimeout(rbusHandle_t handle,int timeout)
 *  @brief  function to update SET Timeout value.
 *
 *  @param      handle         The Bus handle.
 *  @param      timeout        The Timeout value for rbus_set operation in milliseconds,
 *                             set to default value if timeout is Zero.
 *  @return    RBus error code as defined by rbusError_t.
 */
rbusError_t rbusHandle_ConfigSetTimeout(rbusHandle_t handle, uint32_t timeout);

/** @fn int rbusHandle_ConfigGetTimeout(rbusHandle_t handle,int timeout)
 *  @brief  function to update GET Timeout value.
 *
 *  @param      handle         The Bus handle.
 *  @param      timeout        The Timeout value for rbus_get operation in milliseconds,
 *                             set to default value if timeout is Zero.
 *  @return     RBus error code as defined by rbusError_t.
 */
rbusError_t rbusHandle_ConfigGetTimeout(rbusHandle_t handle, uint32_t timeout);

/** @fn int rbusHandle_ConfigGetMultiTimeout(rbusHandle_t handle,int timeout)
 *  @brief  function to update GET Wildcard query Timeout value.
 *
 *  @param      handle         The Bus handle.
 *  @param      timeout        The Timeout value for rbus_get operation in milliseconds,
 *                             set to default value if timeout is Zero.
 *  @return     RBus error code as defined by rbusError_t.
 */
rbusError_t rbusHandle_ConfigGetMultiTimeout(rbusHandle_t handle, uint32_t timeout);

/** @fn int rbusHandle_ConfigSetMultiTimeout(rbusHandle_t handle,int timeout)
 *  @brief  function to update SetMulti Timeout value.
 *
 *  @param      handle         The Bus handle.
 *  @param      timeout        The Timeout value for rbus_setMulti operation in milliseconds,
 *                             set to default value if timeout is Zero.
 *  @return     RBus error code as defined by rbusError_t.
 */
rbusError_t rbusHandle_ConfigSetMultiTimeout(rbusHandle_t handle, uint32_t timeout);

/** @fn int rbusHandle_ConfigSubscribeTimeout(rbusHandle_t handle,int timeout)
 *  @brief  function to update Subscribe Timeout value.
 *
 *  @param      handle         The Bus handle.
 *  @param      timeout        The Timeout value for Subscribe operation in milliseconds,
 *                             set to default value if timeout is Zero.
 *  @return     RBus error code as defined by rbusError_t.
 */
rbusError_t rbusHandle_ConfigSubscribeTimeout(rbusHandle_t handle, uint32_t timeout);
/** @} */

#ifdef __cplusplus
}
#endif

#endif

/** @} */
