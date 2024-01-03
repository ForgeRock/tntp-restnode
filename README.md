# HTTP Request

The **HTTP Request** node enables HTTP(S) requests to be made to external APIs and services directly from within a [journey](https://backstage.forgerock.com/docs/idcloud/latest/realms/journeys.html).

This node can be used to simplify integration with a broad range of external services such as REST APIs to invoke actions or retrieve data for use in subsequent nodes in a journey.
The node can be configured to make GET, POST, PUT, DELETE, PATCH and HEAD requests, include headers, request parameters, payloads, and send certificates for endpoints secured using mTLS. The node also allows response body contents to be saved to shared state and response codes to be handled by configurable outcomes.

Identity Cloud provides these artifacts for HTTP Request authentication journeys:

- [HTTP Request node](#)

## Quick start with sample journeys

Identity Cloud provides sample journeys to help you understand some common uses cases for HTTP Request. To use the samples, perform these steps:

1. Download the JSON files for sample journeys from [here](#).
2. Import the downloaded sample journeys into your Identity Cloud environment.

For more information on sample journeys, refer to [HTTP Request sample journeys.](#)

## Setup

No specific setup steps are required to use this node, however, if you wish to use this node to make calls to Mutual Transport Layer Security (mTLS) secured endpoints then a valid X.509 digital certificate must be provided. The node should be configured with both the public certificate and private key components in PEM format. These values can be simply added to the node configuration or, for greater flexibility and ease of management it is recommended to use [Identity Cloud ESVs](https://backstage.forgerock.com/docs/idcloud/latest/tenants/esvs.html).   


# HTTP Request Node

The **HTTP Request** node enables HTTP(S) requests to be made to external APIs and services directly from within a [journey](https://backstage.forgerock.com/docs/idcloud/latest/realms/journeys.html).

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

| Property                   | Usage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Rest URL                   | The endpoint URL including scheme, port (optional), and path (optional). For example:<br><br>https://postman-echo.com/post<br><br>You can automatically add values from shared state by including the shared state variable name in handlebars {{variable}} notation, for example:<br><br>https://postman-echo.com/postman/{{username}}/account<br><br>where "username" is currently set in shared state.                                                                                                                                                                                                                                                                                                                                                                                                           
| Request Type               | Select the request type: GET, POST, PUT, DELETE, PATCH or HEAD.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Query Parameters           | An optional set of key/value pairs which will be added as query parameters. You can automatically add values from shared state by including the shared state variable name in handlebars {{variable}} notation, for example:<br><br>- Key: user_id<br>- Value: {{username}}<br><br> to include a query parameter called "user_id" to the value of *username* in shared state.                                                                                                                                                                                                                                                                                                                                                                                                                                       
| Headers                    | An optional set of key/value pairs which will be added as request headers. You can automatically add values from shared state by including the shared state variable name in handlebars {{variable}} notation, for example:<br><br>- Key: X-Transaction-ID<br>- Value: {{username}}<br><br> to include a header called "X-Transaction-ID" to the value of *username* in shared state.                                                                                                                                                                                                                                                                                                                                                                                                                               
| Payload                    | An optional value to include as the request payload or body. The payload format will depend on the REST endpoint but may include JSON, XML, plain text, or other data. You can automatically include values from shared state by including the shared state variable name(s) in handlebars {{variable}} notation. For example, the following will include a JSON payload with values automatically substituted from shared state variables:<br><br>`{ "uid": "{{username}}", "first_name":{{givenName}}, "last_name":{{sn}}, "active": true }`<br><br>An example of a *form* payload (application/x-www-form-urlencoded):<br><br>`uid={{username}}&first_name={{givenName}}&last_name={{sn}}&active=true`<br><br>Note: if requested shared state variables are not set, then a value of *null* will be substituted. 
| Body Type                  | Select the request body type: XWWWFORMURLENCODED, JSON, XML or PLAIN.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Use mTLS                   | Enable this to include a client X.509 digital certificate with the request for endpoints requiring Mutual TLS. If enabled then also configure the *Public Certificate* and *Private Key* values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Public Certificate         | An X.509 public certificate in PEM format. See also the recommendations in the Setup section on the use of ESV values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Private Key                | The private key for the X.509 certificate in PEM format. See also the recommendations in the Setup section on the use of ESV values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Disable Certificate Checks | If this option is enabled then certificate errors (e.g., certificate expired) associated with the external endpoint are ignored. Note, trusting expired and invalid certificates can have serious security implications so this setting should be used for test purposes only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Response Codes             | By default the node has *Success* and *Error* outcomes. Here you can optionally specify other response codes to add new outcomes. For example, adding `200` and `401` will add 2 additional outcomes in order to handle `OK` and `Unauthorized` outcomes respectively. Response code classes can be used to handle ranges, for example, to capture all *Client error* responses (codes 400-499) and *Server error* responses (codes 500-599) add the values `4xx` and `5xx` respectively. This will result in 2 additional outcomes which can be handled appropriately in the journey.                                                                                                                                                                                                                              
| Status Code SharedState Variable | (Optionally) specify the name of a shared state variable in which to store the request response code.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Returned Body SharedState Variable | (Optionally) specify the name of a shared state variable in which to store the request response body. |
| Timeout (seconds) | Specify a timeout value (in seconds) for the request. The same timeout value is used for both establishing a connection to the endpoint and for awaiting a response. |

## Outputs

---

Response code values and response body data can be optionally saved to shared state for subsequent use by the journey. See the Configuration section for details.

## Outcomes

---

***Success***

- The request successfully completed.

***Error***

- An error occurred causing the request to fail. Check the response code, response body, or logs to see more details of the error.

***Specific Codes***

- Outcomes for specific response codes (for example, 401), and response code classes (for example, 2xx) can also be dynamically configured. See the *Response Code* property in the Configuration section for more details.

## Troubleshooting

---

If this node logs an error, review the log messages the find the reason for the error and address the issue appropriately. There are also many publicly accessible test endpoints which can be used to help test and troubleshoot with this node. For example https://httpstat.us and https://postman-echo.com.  

## Examples

---