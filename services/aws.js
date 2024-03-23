// Info: Contains Functions AWS specific HTTP Requests
'use strict';

// Shared Dependencies (Managed by Main Entry Module & Loader)
var Lib;

// Exclusive Dependencies
var CONFIG; // (Managed by Main Entry Module & Loader)


/////////////////////////// Module-Loader START ////////////////////////////////

  /********************************************************************
  Load dependencies and configurations

  @param {Set} shared_libs - Reference to libraries already loaded in memory by other modules
  @param {Set} config - Custom configuration in key-value pairs

  @return nothing
  *********************************************************************/
  const loader = function(shared_libs, config){

    // Shared Dependencies (Managed my Main Entry Module)
    Lib = shared_libs;

    // Configuration (Managed my Main Entry Module)
    CONFIG = config;

  };

//////////////////////////// Module-Loader END /////////////////////////////////



///////////////////////////// Module Exports START /////////////////////////////
module.exports = function(shared_libs, config){

  // Run Loader
  loader(shared_libs, config);

  // Return Public Funtions of this module
  return HttpAws;

};//////////////////////////// Module Exports END //////////////////////////////



///////////////////////////Public Functions START//////////////////////////////
const HttpAws = { // Public functions accessible by other modules

  /********************************************************************
  Set 'AWS Lambda' specific data into Instance Object.

  @param {Map} instance - instance object that is to be modified
  @param {Map} event - event data that executed this module. data from API Gateway (AWS Lambda)
  @param {Map} request_context - AWS Lambda execution related data
  @param {function} response_callback - The calback for final output. Data sent to API Gateway

  @return {Void} - Returns nothing but updates the passed 'Instance Object'
  *********************************************************************/
  loadHttpDataFromLambdaToInstance: function(instance, event, request_context, response_callback){

    // Print 'event' data for debugging
    //Lib.Debug.log( 'Event Data: ' + JSON.stringify(event) );

    // Default Data
    instance['gateway_response_callback'] = null; // Store reference to API gateway response callback
    instance['auth'] = {
      'token'         : null, // Authorization Token (In case of Authorization Service Only)
      'method_id'     : null, // Method ARN for whom this authentication is being done
      'custom_data'   : null, // Custom-Data saved in API Gateway authorizer (Usually used to cache session-tokens and session-data)
    };
    instance['http_request'] = { // HTTP Request Data recieved from API Gateway
      'headers'       : {},   // HTTP Request Headers
      'cookies'       : {},   // Cookies sent with this request
      'get'           : {},   // HTTP GET Params
      'post'          : {},   // HTTP POST Params
      'path'          : {},   // HTTP PATH Params
      'files'         : {},   // Binary FILES uploaded in this request
      'method'        : null  // HTTP Request Method - GET | POST | ...
    };
    instance['http_response'] = { // HTTP Response Data to be sent out
      'cookies'   : {}, // Cookies to be sent in response as serialized string in 'Set-Cookie' key
    };

    // Lock Cleanup until response is sent to gateway
    instance['cleanup_locked'] = true;

    // Set Lambda response-Return function
    instance['gateway_response_callback'] = function(...args){
      response_callback(...args); // forward args to gateway
      instance['cleanup_locked'] = false; // Unlock Cleanup
    }


    // Only proceed if 'event' is defined
    if( Lib.Utils.isNullOrUndefined(event) ){
      return; // If empty event then stop here
    }


    // Set authorization Data
      // Auth Token (Only in-case of Service authorization)
      if( 'authorizationToken' in event && event['authorizationToken'] ){
        instance['auth']['token'] = event['authorizationToken'];
      }

      // Auth Method ID (Only in-case of Service authorization)
      if( 'methodArn' in event && event['methodArn'] ){
        instance['auth']['method_id'] = event['methodArn'];
      }

      // Custom-Data saved in API Gateway authorizer (Usually used to cache session-tokens and session-data) (Only in-case of API Gateway authorizer)
      if(
        'requestContext' in event &&
        'authorizer' in event['requestContext'] &&
        !Lib.Utils.isNullOrUndefined( event['requestContext']['authorizer']['stringKey'] ) &&
        event['requestContext']['authorizer']['stringKey'].length > 0
      ){
        instance['auth']['custom_data'] = Lib.Utils.stringToJSON( event['requestContext']['authorizer']['stringKey'] ); // De-flat flattened JSON sent by authorizer
      }


    // Extract and set HTTP request data
      // Headers
      if( 'headers' in event && event['headers'] ){

        // Convert & copy all Header Keys to lower case. Also Convert Cloudfront Headers to Generic Names
        var header_Keys = Object.keys(event['headers']);
        console.log('header_Keys: ', header_Keys)

        // List of relevent known AWS Cloudfront headers
        const vendor_headers = {
          'cloudfront-viewer-country': 'viewer-country',
          'cloudfront-is-tablet-viewer': 'is-tablet-viewer',
          'cloudfront-is-smarttv-viewer': 'is-smarttv-viewer',
          'cloudfront-is-mobile-viewer': 'is-mobile-viewer',
          'cloudfront-is-desktop-viewer': 'is-desktop-viewer',
        }

        // Iterate all headers
        header_Keys.forEach(function(header_key, i){

          // Convert to Lowercase
          header_key = header_key.toLowerCase();
          console.log('header_key: ', header_key)

          // Convert Cloudfront Headers to Generic Names
          if( header_key in vendor_headers ){
            instance['http_request']['headers'][vendor_headers[header_key]] = event['headers'][header_Keys[i]]
          }
          else{ // Convert same key to lowercase
            instance['http_request']['headers'][header_key] = event['headers'][header_Keys[i]]
          }

        });

      }

      // Cookies [API Gateway v1.0 Payload]
      if( 'cookie' in instance['http_request']['headers'] && instance['http_request']['headers']['cookie'] ){
        instance['http_request']['cookies'] = Lib.Cookie.parse( instance['http_request']['headers']['cookie'] ); // Split multiple cookies string into Key-Value set
      }
      // Cookies [API Gateway v2.0 Payload]
      else if( 'cookies' in event && event['cookies'] ){
        instance['http_request']['cookies'] = Object.assign( ...event['cookies'].map(cookie=>Lib.Cookie.parse(cookie)) ); // Convert each cookie string into key-value set
      }


      // GET Parameters
      if( 'queryStringParameters' in event && event['queryStringParameters'] ){
        instance['http_request']['get'] = event['queryStringParameters']; // Copy All Get params
      }

      // PATH Parameters
      if( 'pathParameters' in event && event['pathParameters'] ){
        instance['http_request']['path'] = event['pathParameters']; // Copy All Path params
      }

      // POST & FILES Parameters
      if(
        'content-type' in instance['http_request']['headers'] &&
        'body' in event &&
        instance['http_request']['headers']['content-type'] && // not null or empty
        event['body'] // not null or empty
      ){
        instance['http_request']['post'] = _HttpAws.getRequestPostParams( // Extract Post params from multipart body
          instance['http_request']['headers']['content-type'],
          event['isBase64Encoded'],
          event['body']
        );
      }

      // HTTP Method [API Gateway v1.0 Payload]
      if( 'httpMethod' in event ){
        instance['http_request']['method'] = event['httpMethod'];
      }
      // HTTP Method [API Gateway v2.0 Payload]
      if(
        'requestContext' in event && event['requestContext'] &&
        'http' in event['requestContext'] && event['requestContext']['http'] &&
        'method' in event['requestContext']['http']

      ){
        instance['http_request']['method'] = event['requestContext']['http']['method'];
      }

    // Return Nothing.

  },


  /********************************************************************
  Build HTTP response object for AWS

  @param {integer} status - response HTTP Status code
  @param {(string|string[])} [headers] -  (optional) array list of response HTTP headers
  @param {object[]} [body] - (optional) response HTTP body

  @return {(string|string[])} - Associative Array with data to be fed to HTTP response
  *********************************************************************/
  buildHttpResponseObject: function(status, headers, body){

    // Set headers as empty array if not set or null
    if( Lib.Utils.isNullOrUndefined(headers) ){
      headers = {};
    }


    // Determine if Base64 Encoded Body (Only for Binary Outputs)
    var is_base64_body = false;


    // Process body. Convert body to string (Only if it's object)
    if( Lib.Utils.isNullOrUndefined(body) ){
      body = ''; // Initalize body with empty string if not sent into params
    }

    // If already String, No Change: As-it-is
    else if(
      Lib.Utils.isString(body) // Check if Object (Reach here means JSON Parsable Object)
    ){
      body = body;
    }

    // If Object AND Binary-Data (Buffer), Convert to Base64 String
    else if(
      Lib.Utils.isObject(body) && // Check if Objexct
      Buffer.isBuffer(body) // Check if Object is Binary Data
    ){
      is_base64_body = true;
      body = Lib.Crypto.bufferToBase64(body);
    }

    // If JSON Object, Convert to String
    else if(
      Lib.Utils.isObject(body) // Check if Object (Reach here means JSON Parsable Object)
    ){
      body = JSON.stringify(body);
    }


    // Construct response array
    var response = {
      'isBase64Encoded': is_base64_body,
      'statusCode': status,
      'headers': headers,
      'body': body
    };


    //Return response
    return response;

  },


  /********************************************************************
  Get http request Country Code (user's country code)
  Note: This is AWS API Gateway Specific Feature. Came code will not work with other servers

  @param {reference} instance - Request Instance object reference

  @return {string} - Request Country Code. Null in case unknown country
  *********************************************************************/
  getHttpRequestCountryCode: function(instance){

    // Get IP from HTTP Request
    if('cloudfront-viewer-country' in instance['http_request']['headers']){ // If AWS API Gateway has sent Cloudfront-Viewer headers
      return instance['http_request']['headers']['cloudfront-viewer-country'];
    }

    // Reached here means Fail
    return null; // Return null if unknown country

  },

};///////////////////////////Public Functions END//////////////////////////////



//////////////////////////Private Functions START//////////////////////////////
const _HttpAws = { // Private methods accessible within this modules only

  /********************************************************************
  Extract Post Params from Request body

  @param {String} content_type - HTTP request header with content-type
  @param {Boolean} is_base64_encoded - If Body is Base64 Encoded
  @param {String} body - HTTP request body

  @return {Map} - Associative Array with param-key and Value and FileType
  *********************************************************************/
  getRequestPostParams: function(content_type, is_base64_encoded, body){

    // If content type is not string
    if( !Lib.Utils.isString(content_type) ){
      return {}; // Return Empty data if Invalid Content-Type
    }


    // Decode Base64 Encoded Body
    if(is_base64_encoded){ // If Base64 Encoded Body
      body = Lib.Crypto.base64ToString(body);
    }


    // Clean Content Type for comparision (Ex: application/json; charset=utf-8)
    var content_type_clean = content_type.split(';')[0].trim();


    // If Content type is application/x-www-form-urlencoded
    if( content_type_clean === `application/x-www-form-urlencoded` ){

      // Node JS inbuilt module to decode and convert query string into JSON Object
      const querystring = require('querystring');

      // Return Data and Do not proceed
      return querystring.parse(body);

    }


    // If Content type is application/json
    else if( content_type_clean === `application/json` ){

      // Return Data and Do not proceed
      return Lib.Utils.stringToJSON(body);

    }


    // TODO: If Content type is Multipart Form-Data
    else if( content_type_clean === `multipart/form-data` ){

      // TODO
      var boundry = content_type.split(';')[1].trim();

      // Return as-it-is for now
      return body;

    }


    // Reach here means unknown content type
    return {}; // Return Empty data if Unknown Content-Type

  },

};//////////////////////////Private Functions END//////////////////////////////
