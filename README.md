# HTTP Client

The **HTTP Client** node enables HTTP(S) requests to be made to external APIs and services directly from within a [journey](https://backstage.forgerock.com/docs/idcloud/latest/realms/journeys.html).

This node can be used to simplify integration with a broad range of external services such as REST APIs to invoke actions or retrieve data for use in subsequent nodes in a journey.
The node can be configured to make GET, POST, PUT, DELETE, PATCH and HEAD requests, include headers, request parameters, payloads, and send certificates for endpoints secured using mTLS. The node also allows response body contents to be saved to shared state and response codes to be handled by configurable outcomes.

Identity Cloud provides these artifacts for HTTP Client authentication journeys:

- [HTTP Client node](#)

## Quick start with sample journeys

Identity Cloud provides sample journeys to help you understand some common uses cases for HTTP Client. To use the samples, perform these steps:

1. Download the JSON files for sample journeys from [here](#).
2. Import the downloaded sample journeys into your Identity Cloud environment.

For more information on sample journeys, refer to [HTTP Client sample journeys.](#)

## Setup

No specific setup steps are required to use this node, however, if you wish to use this node to make calls to Mutual Transport Layer Security (mTLS) secured endpoints then a valid X.509 digital certificate must be provided. The node should be configured with both the public certificate and private key components in PEM format. These values can be simply added to the node configuration or, for greater flexibility and ease of management it is recommended to use [Identity Cloud ESVs](https://backstage.forgerock.com/docs/idcloud/latest/tenants/esvs.html).   


# HTTP Client Node

The **HTTP Client** node enables HTTP(S) requests to be made to external APIs and services directly from within a [journey](https://backstage.forgerock.com/docs/idcloud/latest/realms/journeys.html).

## Compatibility

---

You can implement this node on the following systems:

| Product | Compatible |
|---------|------------|
| ForgeRock Identity Cloud | Yes |
| ForgeRock Access Management (self-managed) | Yes |
| ForgeRock Identity Platform (self-managed) | Yes |

## Inputs

---
Any data in shared state that should be included in headers, request parameters, or payload/body of the request.

## Dependencies

---

This node has no other dependencies.

## Configuration

| Property                            | Usage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Rest URL                            | The endpoint URL including scheme, port (optional), and path (optional). For example:<br><br>https://postman-echo.com/post<br><br>You can automatically add values from shared state by including the shared state variable name in handlebars {{variable}} notation, for example:<br><br>https://postman-echo.com/postman/{{username}}/account<br><br>where "username" is currently set in shared state. <br><br>JSONpath expressions can also be used here to select specific values or branches from JSON objects stored in shared state variables. See the section on "Value Substitution" below for more details.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
| Request Method                      | Select the request type: GET, POST, PUT, DELETE, PATCH or HEAD.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Query Parameters                    | An optional set of key/value pairs which will be added as query parameters. You can automatically add values from shared state by including the shared state variable name in handlebars {{variable}} notation, for example:<br><br>- Key: user_id<br>- Value: {{username}}<br><br> to include a query parameter called "user_id" to the value of *username* in shared state. <br><br>JSONpath expressions can also be used here to select specific values or branches from JSON objects stored in shared state variables. See the section on "Value Substitution" below for more details.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
| Headers                             | An optional set of key/value pairs which will be added as request headers. You can automatically add values from shared state by including the shared state variable name in handlebars {{variable}} notation, for example:<br><br>- Key: X-Transaction-ID<br>- Value: {{username}}<br><br> to include a header called "X-Transaction-ID" to the value of *username* in shared state. <br><br>JSONpath expressions can also be used here to select specific values or branches from JSON objects stored in shared state variables. See the section on "Value Substitution" below for more details.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
| Use HTTP "Basic" Authentication     | Enable this to include a HTTP "Basic" Authentication header.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
| HTTP "Basic" Username               | The username for HTTP "Basic" Authentication.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
| HTTP "Basic" Password               | The password for HTTP "Basic" Authentication.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
| Body Content                        | An optional value to include as the request payload or body. The payload format will depend on the REST endpoint but may include JSON, XML, plain text, or other data. You can automatically include values from shared state by including the shared state variable name(s) in handlebars {{variable}} notation. For example, the following will include a JSON payload with values automatically substituted from shared state variables:<br><br>`{ "uid": "{{username}}", "first_name":{{givenName}}, "last_name":{{sn}}, "active": true }`<br><br>An example of a *form* payload (application/x-www-form-urlencoded):<br><br>`uid={{username}}&first_name={{givenName}}&last_name={{sn}}&active=true`<br><br>Note: if requested shared state variables are not set, then a value of *null* will be substituted. <br><br>JSONpath expressions can also be used here to select specific values or branches from JSON objects stored in shared state variables. See the section on "Value Substitution" below for more details.                                                                                                                                                                                                                             
| Body Content Encoding               | Select the request body type: XWWWFORMURLENCODED, JSON, XML or PLAIN.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Use mTLS                            | Enable this to include a client X.509 digital certificate with the request for endpoints requiring Mutual TLS. If enabled then also configure the *Public Certificate* and *Private Key* values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| mTLS Public Certificate             | An X.509 public certificate in PEM format. See also the recommendations in the Setup section on the use of ESV values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| mTLS Private Key                    | The private key for the X.509 certificate in PEM format. See also the recommendations in the Setup section on the use of ESV values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Disable Certificate Checks          | If this option is enabled then certificate errors (e.g., certificate expired) associated with the external endpoint are ignored. Note, trusting expired and invalid certificates can have serious security implications so this setting should be used for test purposes only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Timeout (seconds)                   | Specify a timeout value (in seconds) for the request. The same timeout value is used for both establishing a connection to the endpoint and for awaiting a response.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Response Codes                      | By default the node has *Default Response* and *Error* outcomes. Here you can optionally specify other response codes to add new outcomes. For example, adding `200` and `401` will add 2 additional outcomes in order to handle `OK` and `Unauthorized` outcomes respectively. Response code classes can be used to handle ranges, for example, to capture all *Client error* responses (codes 400-499) and *Server error* responses (codes 500-599) add the values `4xx` and `5xx` respectively. This will result in 2 additional outcomes which can be handled appropriately in the journey. <br><br>Note: If any JSON Response Outcome (see below) is also matched, that will take precedence over any Response Code outcome defined here.                                                                                                                                                                                                                                                                                                            
| Status Code Shared State Variable   | (Optionally) specify the name of a shared state variable in which to store the request response code.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Returned Body Shared State Variable | (Optionally) specify the name of a shared state variable in which to store the request response body.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| JSON Response Handler               | For REST calls which return a JSON formatted response, specific returned values or JSON paths of the response can be mapped to shared state variables. Define these are key/value pairs where the key is the shared state variable name and the value is the JSONpath expression of the data to be saved. See the "Value Substitution" section below for details on JSONpath expressions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| JSON Response Outcome Handler       | For REST calls which return a JSON formatted response, specific returned values can be evaluated and used to trigger appropriate outcomes for the node. You can use this, for example, to test for specifiec returned values which should be handled by different branches of the subsequent journey steps. Outcomes are defined by key/value pairs, where the key is the name of the outcome, and the value is the JSONpath expression which should be evaluated on the returned JSON data. JSONpath expressions act as filters on JSON arrays of data. An expression which results in a non-empty array is considered a successfuly match and should trigger the associated outcome. See the "Value Substituion" section below for details on JSONpath expressions. <br><br>Note: an outcome matched by this JSON Response Outcome Handler will override any Response Code outcomes defined. For example, if a Response Code outcome is defined for code "200" but the JSON Response Outcome is also matched then the latter will be followed. |


### Value Substitution

A number of configuration properties allow values to be retrieved or saved to shared state variables. 
For these properties, variable substitution using handle bars notation, e.g., {{variable}}, can be used.
For example, to automaticall include "username" within a URL path you can use an expression similar to this:<br><br>https://postman-echo.com/postman/{{username}}/account<br><br>
where "username" is the name of a variable currently set in shared state.

If the value in shared state is a JSON object, then [JSONpath](https://github.com/json-path/JsonPath/blob/master/README.md) 
notation may be used to select specific values, array items, or complete branches of the JSON object.   

To use JSONpath expressions for variable subsitution, use an expression of the form `<shared state variable>.$.<path>`

for example, given a shared state variable called "objectAttributes" containing this JSON data:

```
{
  "username": "bob",
  "firstName": "Bob",
  "lastname": "Fleming",
  "telephoneNumber": "+1(555)1231234",
  "bookingIDs": [ 29872, 23884, 48382 ],
  "membershipTier": "platinum"
}
```

the "firstname" and "lastname" attributes can be selected as `{{objectAtttributes.$.firstname}}` and `{{objectAttributes.$.lastname}}` respectively.
The last booking ID can be selected as `{{objectAttributes.$.bookingIDs[2]}}` or `{{objectAttributes.$.bookingIDs[-1]}}`.

Similar notation can be used with the JSON Response Handler property to save returned JSON response values to shared state.
For example, if the JSON object above is the response to a REST API call, then a JSON Response Handler configuration with key/value as follows will select the telephone number from the response and save it to shared state variable "phone":

- Key: phone
- Value: $.telephoneNumber

The JSON Response Outcome Handler can be filtered with a suitable JSONpath expression to look for matching responses.
A matching outcome is triggered when the JSONpath expression, when applied to an array containing the JSON response, results in a non-empty array, i.e., the expression finds at least one match.
For example, if the JSON object above is the response to a REST API call, then a JSON Response Outcome Handler configuration with key/value as follows will trigger the "Priority" outcome:

- Key: Priority
- $.[?(@.membershipTier == 'platinum')]

Full details of [JSONpath](https://github.com/json-path/JsonPath/blob/master/README.md) expressions can be found [here](https://github.com/json-path/JsonPath/blob/master/README.md).


## Outputs

---

Response code values and response body data can be optionally saved to shared state for subsequent use by the journey. 
See the Configuration section for details.

## Outcomes

---

***Matching JSONpath Outcomes***

- Outcomes for specific JSON response data can be added. See the *JSON Response Outcome Handler* property for more details.

***Response Codes***

- Outcomes for specific response codes (for example, 401), and response code classes (for example, 2xx) can also be dynamically configured. See the *Response Code* property in the Configuration section for more details.

***Default Response***

- The request completed but no other JSONpath outcome or response code outcomes matched. Note: this outcome means a request and response were successfully processed, including responses indicating errors, for example, 4xx meaning "client error". If these should be handled then consider adding Response Code outcomes too.  

***Error***

- An error occurred causing the request to fail. Check the response code, response body, or logs to see more details of the error.

Note: In cases where multiple outcomes might apply, they are triggered according to the priority order listed above. For example, a REST call might result in both a matching JSON response outcome as well as a 200 response code outcome. The matched JSON response outcome is triggered in this case.



## Troubleshooting

---

If this node logs an error, review the log messages the find the reason for the error and address the issue appropriately. There are also many publicly accessible test endpoints which can be used to help test and troubleshoot with this node. For example https://httpstat.us and https://postman-echo.com.  

## Examples

---
