// Info: Boilerplate library. Contains Functions for Incoming HTTP(s) request and its return Response.
'use strict';

// Shared Dependencies (Managed by Loader)
var Lib = {};

// URL Parser Library (Private scope)
const UrlParser = require('tldts');

// Exclusive Dependencies
var CONFIG = require('./config'); // Loader can override it with Custom-Config
const HttpService = {}; // Managed by Loader


/////////////////////////// Module-Loader START ////////////////////////////////

  /********************************************************************
  Load dependencies and configurations

  @param {Set} shared_libs - Reference to libraries already loaded in memory by other modules
  @param {Set} config - Custom configuration in key-value pairs

  @return nothing
  *********************************************************************/
  const loader = function(shared_libs, config){

    // Shared Dependencies (Must be loaded in memory already)
    Lib.Utils = shared_libs.Utils;
    Lib.Debug = shared_libs.Debug;
    Lib.Crypto = shared_libs.Crypto;
    Lib.Instance = shared_libs.Instance;

    // Override default configuration
    if( !Lib.Utils.isNullOrUndefined(config) ){
      Object.assign(CONFIG, config); // Merge custom configuration with defaults
    }

    // Cookie Parser Library (Private scope)
    Lib.Cookie = require('cookie');

    // Exclusive Dependencies
    HttpService['aws'] = require('./services/aws.js')(Lib);

  };

//////////////////////////// Module-Loader END /////////////////////////////////



///////////////////////////// Module Exports START /////////////////////////////
module.exports = function(shared_libs, config){

  // Run Loader
  loader(shared_libs, config);

  // Return Public Funtions of this module
  return HttpHandler;

};//////////////////////////// Module Exports END //////////////////////////////



///////////////////////////Public Functions START//////////////////////////////
const HttpHandler = { // Public functions accessible by other modules

  /********************************************************************
  Initialize Http request data in Instance from raw http gataway data

  @param {Map} instance - instance object that is to be modified
  @param {Map} request_data - Http raw data from HTTP interface. (Data Sent from from API Gateway to AWS Lambda)
  @param {Map} request_context - This request specific context sent to process. (AWS Lambda)
  @param {Function} response_callback - The calback to return response back to HTTP interface. (Data sent to API Gateway)

  @return {Void} - Returns nothing but updates the passed 'Instance Object'
  *********************************************************************/
  initHttpRequestData: function(instance, request_data, request_context, response_callback){

    // Add HTTP related to Instance. Forward to specific http provider
    HttpService[CONFIG.HTTP_PROVIDER].loadHttpDataFromLambdaToInstance(
      instance,
      request_data,
      request_context,
      response_callback,
    );

    // Return Nothing.

  },


  /********************************************************************
  Check if HTTP-Request is Initialized in 'instance'

  @param {reference} instance - Request Instance object reference

  @return {Boolean} - true if Lambda is executed by HTTP Gateway
  @return {Boolean} - false if Lambda is not executed by HTTP Gateway
  *********************************************************************/
  isHttpInstance: function(instance){

    // Check if http request data exists in 'instance' object
    if(
      !Lib.Utils.isNullOrUndefined(instance['http_request']) &&
      instance['http_request'] !== false
    ){
      return true;
    }
    else{
      return false;
    }

  },


  /********************************************************************
  Create an 'args' input object from http request params. Also Set defaults, Sanitize and Set Type

  @param {reference} instance - Request Instance object reference
  @param {Map[]} params - list of each param and rules
  * @param {Map} - Each param set
  * * @param {String} method - GET|POST|PATH|HEADER|FIXED
  * * @param {String} name - Name of parameter
  * * @param {String} rename - Rename parameter
  * * @param {String} value - Value (Incase of Custom)
  * * @param {Boolean} required - Whether this Parameter is Required or optional
  * * @param {Object} default - Default Value if it's an optional param. (Set NULL for required parameters)
  * * @param {Boolean} is_number - Whether this parameter is a Number
  * * @param {Boolean} is_boolean - Whether this parameter is a Boolean
  * * @param {Boolean} is_json - Whether this parameter is a stringified json
  * * @param {Boolean} trim - Whether to trim Empty spaces from string param
  * * @param {Function} json_func - Function for translating JSON Object
  * * @param {Function} validate_func - Function for Input validation
  * * @param {Function} invalidate_func - Function for Input invalidation

  @return [ {Error[]}, {Map[]} ] - Array of object with all the parameters on success | Array of Params
  @return [ {Null}, {Boolean} ] - Null | false if required parameters are not sent.
  *********************************************************************/
  setArgsFromHttpRequestData: function( instance, params ){

    // Initialize output object
    var errs = false;
    var args = {};


    // If empty param array then return empty array
    if( Lib.Utils.isNullOrUndefined(params) || params.length == 0 ){
      return [errs, args];
    }


    // Start checking each param. Copy it to clean args array
    params.every(function(param){ // 'every' is 'forEach' alternative that allows to break loop

      // Initalize temporary variable to hold param value
      var param_value = null;

      if( param['method'] === 'GET' && (param.name in instance['http_request']['get']) ){
        param_value = instance['http_request']['get'][param.name];
      }
      else if( param['method'] === 'POST' && (param.name in instance['http_request']['post']) ){
        param_value = instance['http_request']['post'][param.name];
      }
      else if( param['method'] === 'HEADER' && (param.name in instance['http_request']['headers']) ){
        param_value = instance['http_request']['headers'][param.name];
      }
      else if( param['method'] === 'PATH' && (param.name in instance['http_request']['path']) ){
        param_value = instance['http_request']['path'][param.name];
      }
      else if( param['method'] === 'FIXED' ){
        param_value = param['value'];
      }


      // Debug Pre-Cleaned raw value
      Lib.Debug.log('Raw ', `${param.name}: ${param_value}`);

      // If any of the required parameter is not found or null the return false (Do not use empty check, other wise empty strings will be rejected as well)
      if( param['required'] && Lib.Utils.isNullOrUndefined(param_value) ){
        args = false; // Failed. Return false as response
        return false; // Exit Loop
      }


      // If param is sent, then copy it to output array after cleaning
      if( !Lib.Utils.isNullOrUndefined(param_value) ){

        // Trim empty spaces (Only if value is string)
        if( ('trim' in param) && param['trim'] && Lib.Utils.isString(param_value) ){

          param_value = param_value.trim();

          // If empty string (Zero length), convert it to null
          if( Lib.Utils.isEmptyString(param_value) ){
            param_value = null; // Covert empty string to null
          }

        }

        // Typecast number properly (Only if value is string)
        if( ('is_number' in param) && param['is_number'] && Lib.Utils.isString(param_value) ){
          param_value = Number(param_value);
        }

        // Typecast boolean properly
        if( ('is_boolean' in param) && param['is_boolean'] ){
          param_value = Boolean( Number(param_value) ); // Convert string -> number -> boolean
        }

        // Typecast json-map properly (Only if value is string)
        if( ('is_json' in param) && param['is_json'] && Lib.Utils.isString(param_value) ){
          try{ param_value = JSON.parse(param_value); } // Convert string -> JSON
          catch(e){
            param_value = null; // Set as null if invalid json

            // Check if its a required parameter
            if( param['required'] ){
              args = false; // Failed. Return false as response
              return false; // Exit Loop
            }

          }

        }

        // JSON Translator
        if(
          'is_json' in param &&  // If JSON
          !Lib.Utils.isNullOrUndefined(param['json_func']) // If JSON Translator function is sent
        ){
          param_value = param['json_func'](param_value); // Translate JSON
        }

        // Sanitize Input
        if(
          'sanatize_func' in param &&  // If any sanatization function is sent
          !Lib.Utils.isNullOrUndefined(param_value) // Value is not null or undefined
        )
          param_value = param['sanatize_func'](param_value); // Call sanitazation function

        // Copy final value to output array
        args[param.rename] = param_value;

      }
      else{ // Set Default value if param's value is NULL
        args[param.rename] = param['default'];
      }


      // Debug Cleaned value
      Lib.Debug.log('Clean ', param.name + ': ' + Lib.Utils.isObject(param_value)?JSON.stringify(param_value):param_value );


      // Recheck for required parameter (In case of typecast of empty string and objects)
      if( param['required'] && Lib.Utils.isNullOrUndefined(param_value) ){
        args = false; // Failed. Return false as response
        return false; // Exit Loop
      }


      // Validate Input
      if(
        'validate_func' in param &&  // If any validation function is sent
        !Lib.Utils.isNullOrUndefined(param_value) && // Value is not null or undefined
        !param['validate_func'](param_value) // Validation fails
      ){
        args = false; // Failed. Return false as response
        return false; // Exit Loop
      }


      // In-Validate Input
      if(
        'invalidate_func' in param &&  // If any validation function is sent
        !Lib.Utils.isNullOrUndefined(param_value) // Value is not null or undefined
      ){

        // Run invalidation function
        let err = param['invalidate_func'](param_value);

        // Return
        if( err ){
          errs = err; // Move to errors list
          args = false; // Failed. Return false as response
          return false; // Exit Loop
        }

      }


      // Return true to continue loop for next element in array
      return true;

    });


    // Return errs and args array
    return [errs, args]; // Return error list and args.

  },


  /********************************************************************
  Return http response data to Http gateway

  @param {reference} instance - Request Instance object reference
  @param {Integer} status - gateway-response HTTP Status code
  @param {Map} [headers] - (optional) array list of gateway-response HTTP headers
  @param {Object} [body] - (optional) gateway-response HTTP body

  @return {VOID} - Send response data directly to http-gateway callback
  *********************************************************************/
  returnHttpResponseToGateway: function(instance, status, headers, body){

    // Initialize final-headers array
    var final_headers = {};

    // Add default Headers to final-headers list
      final_headers['Cache-Control'] = 'max-age=0'; // Default Cache Behaviour - No Caching
      final_headers['Content-Type'] = 'application/json'; // Default Content Type - JSON
      // CORS Header are sometimes managed/owerwritten by HTTP Gateway service provider. AWS API gateway manages them itself.
      //final_headers['Access-Control-Allow-Origin'] = '*'; // Required for CORS support
      // final_headers['Access-Control-Allow-Origin'] = HttpHandler.getHttpRequestOrigin(instance); // Whitelist every origin (Need this so localhost can access apis)
      // final_headers['Access-Control-Allow-Credentials'] = 'true'; // Allow Web page to access credentials like cookies, authorization headers or TLS client certificates


    // Add Set-Cookies to final header
    if( Object.keys(instance['http_response']['cookies']).length > 0 ){
      Object.assign(final_headers, instance['http_response']['cookies']); // Merge arrays
    }


    // Add custom Headers to final headers array
    if( !Lib.Utils.isNullOrUndefined(headers) ){ // Only if custom headers are sent
      Object.assign(final_headers, headers); // Merge arrays
    }


    // Create HTTP-Response Object
    var response = HttpService[CONFIG.HTTP_PROVIDER].buildHttpResponseObject(status, final_headers, body);
    //Lib.Debug.log("headers: " + JSON.stringify(final_headers));
    //Lib.Debug.log("response: " + JSON.stringify(response));


    // Return response
    instance['gateway_response_callback'](null, response);

    // Return true
    return true;

  },


  /********************************************************************
  Return Body-less http-status as response to Http gateway

  @param {reference} instance - Request Instance object reference
  @param {Enum} status_name - Status Name ('not_modified' | 'bad_request' | ...)

  @return {VOID} - Send response data directly to http-gateway callback
  *********************************************************************/
  returnHttpStatusToGateway: function(instance, status_name){

    // Known HTTP Status codes
    const status_codes = {
      'not_modified'      : 304, // 304 Not Modified (When there is no change in data and client already has latest data)
      'bad_request'       : 400, // 400 Bad Request (When a valid endpoint is requested by client but request parameters are not right)
      'unauthorized'      : 401, // 401 Unauthorized (When a valid endpoint is requested by client but session token is invalid or empty)
      'not_found'         : 404, // 404 Not Found (Page is not available. When some invalid url is requested)
      'invalid_token'     : 498, // 498 Custom: Invalid Token (Invalid token recived. When app token is invalid or not sent. Not a standard HTTP status code)
    };


    // Return http response data to Http gateway
    return HttpHandler.returnHttpResponseToGateway(
      instance,
      status_codes[status_name]
    );

  },


  /********************************************************************
  Return a 301 Permanaent redirect to custom location as response to Http gateway

  @param {reference} instance - Request Instance object reference
  @param {String} redirect_location - URI Path

  @return {VOID} - Send data to http-gateway-response callback
  *********************************************************************/
  returnHttpRedirectToGateway: function(instance, redirect_location){

    //Add Redirect location to headers list
    var headers = {
      'Location': redirect_location // Redirect to new location
    };

    // Return Response to API Gateway
    return HttpHandler.returnHttpResponseToGateway(
      instance,
      301,        // Status = 301 Permanaent new location
      headers     // Header
    );

  },


  /********************************************************************
  Redirect to generic /404 page as response to Http gateway
  (When some invalid url is requested)

  @param {reference} instance - Request Instance object reference

  @return {VOID} - Send data to http-gateway-response callback
  *********************************************************************/
  returnHttpRedirect404ToGateway: function(instance){

    // Return Response to API Gateway
    return HttpHandler.returnHttpRedirectToGateway(
      instance,
      '/404'      // Redirect to 404 page
    );

  },


  /********************************************************************
  Get http request IP Address (user's ip address)
  (Some HTTP request may not have IP)

  @param {reference} instance - Request Instance object reference

  @return {string} - Request Origin IP address. Empty string in case of no IP address.
  *********************************************************************/
  getHttpRequestIPAddress: function(instance){

    // Get IP from HTTP Request
    if('x-forwarded-for' in instance['http_request']['headers']){ // If IP Proxy Link chain is sent by API Gateway
      return instance['http_request']['headers']['x-forwarded-for'].split(',' , 1)[0]; // 1st IP in chain is request Origin IP Address (ex: "27.56.130.92, 54.182.231.9")
    }

    // Reached here means Fail
    return ''; // Return empty string as IP address

  },


  /********************************************************************
  Get http request User Agent
  (Some HTTP request may not have UA)

  @param {reference} instance - Request Instance object reference

  @return {string} - Request's User Agent. Empty string in case of no User Agent.
  *********************************************************************/
  getHttpRequestUserAgent: function(instance){

    // Get user-agent from HTTP Request
    if('user-agent' in instance['http_request']['headers']){ // If user-agent sent by API Gateway
      return instance['http_request']['headers']['user-agent'];
    }

    // Reached here means Fail
    return ''; // Return empty string as user-agent

  },


  /********************************************************************
  Get http request Origin
  http://user:pass@api.example.com/p/a/t/h?query=string => http://api.example.com

  @param {reference} instance - Request Instance object reference

  @return {string} - Request's Origin Hostname. Empty string in case of no Origin.
  *********************************************************************/
  getHttpRequestOrigin: function(instance){

    // Get request origin from HTTP Request
    if('origin' in instance['http_request']['headers']){ // If origin sent by API Gateway
      return instance['http_request']['headers']['origin'];
    }


    // Reach here means Fail
    return ''; // Return empty string as request origin

  },


  /********************************************************************
  Get http request Country Code (user's country code)
  Note: This is AWS API Gateway Specific Feature. Came code will not work with other servers

  @param {reference} instance - Request Instance object reference

  @return {string} - Request Country Code. Null in case unknown country
  *********************************************************************/
  getHttpRequestCountryCode: function(instance){

    // Forward to specific service-provider
    return HttpService[CONFIG.HTTP_PROVIDER].getHttpRequestCountryCode(instance);

  },


  /********************************************************************
  Return specific/current unix-timestamp(seconds) in HTTP Date Format
  <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
  Wed, 21 Oct 2015 07:28:00 GMT

  @param {string} [date] - (Optional) Date to be converted into Http Date. If not sent in param, then return current time

  @return {String} - time in HTTP Date format
  *********************************************************************/
  getHttpTime: function(date){

    // Check if custom date is sent
    if( !Lib.Utils.isNullOrUndefined(date) ){
      return( new Date(date*1000).toUTCString() ); // Return HTTP Time equivalant of specific timestamp
    }
    else{
      return( new Date().toUTCString() ); // Return HTTP Time equivalant of current timestamp
    }

  },


  /********************************************************************
  Set Cookie to be sent in HTTP Response

  @param {reference} instance - Request Instance object reference

  @param {String} cookie_name - Name of this cookie
  @param {String} cookie_value - Value of this cookie
  @param {String} cookie_life - Seconds after which this cookie should expire

  @return {undefined} - None
  *********************************************************************/
  setCookie: function(instance, cookie_name, cookie_value, cookie_life){

    // Cookie Options
    var cookie_options = {
      httpOnly: false, // Allow cookie can be accessed thru javascript - So cookie can be accesed by Web-App using apis
      secure: true,   // Only send cookie to server if HTTPS request
      maxAge: cookie_life,  // Persistant Cookie that expires after these many seconds
      // comment to send no domain. To solve cloudfront issue of not sending hostname
      //domain : '.' + instance['http_request']['headers']['host'], // If a domain is specified, subdomains are always included otherwise not if domain not specified (.example.com)
      path: '/'       // Root Access Path
    };


    // Set SameSite->None only if Compatible Browser
    if( !_HttpHandler.isSameSiteNoneIncompatible( HttpHandler.getHttpRequestUserAgent(instance) ) ){
      cookie_options['sameSite'] = 'none'; // Allow access to localhost and different Web-Domain
    }


    // Set Cookie Request
    instance['http_response']['cookies']['Set-Cookie'] = _HttpHandler.serializeCookie(
      cookie_name,
      cookie_value,
      cookie_options
    );

  },


  /********************************************************************
  Extract different parts of url (http://www.abc.example.co.us:8080)

  @param {string} url - URL from which parts are to be extracted


  @return {Set} - Url Parts as object
  * @param {String} sub_domain - Sub-Domain ('www.abc')
  * @param {String} domain - domain ('example.co.us')
  * @param {String} domain_without_tld - domain without TLD ('example')
  * @param {String} tld - TLD ('co.us')
  * @param {String} hostname - Host Name ('www.example.co.us')
  * @param {Boolean} is_ip - If this URL is IP address and not Icann-url
  *********************************************************************/
  getUrlParts: function(url){

    const url_parts = UrlParser.parse(url);

    return ({
      'sub_domain': url_parts['subdomain'],
      'domain': url_parts['domain'],
      'domain_without_tld': url_parts['domainWithoutSuffix'],
      'tld':  url_parts['publicSuffix'],
      'hostname': url_parts['hostname'],
      'is_ip':  url_parts['isIp']
    });

  },


  /********************************************************************
  TODO: Convert Simple JS Set Object to Multipart Form Data
  Multipart Parser (Finite State Machine)
  Ref: https://github.com/freesoftwarefactory/parse-multipart

  @param {String|Buffer} body - Multipart Body as String
  @param {String} boundary - Boundary

  @return [{Set},{Set}] [params, files] - Params and Files
  *********************************************************************/
  formDataToJsObject: function(body, boundary){
    // TODO
  },

}; // Close Public Functions

////////////////////////////Public Functions END///////////////////////////////



//////////////////////////Private Functions START//////////////////////////////
const _HttpHandler = { // Private methods accessible within this modules only

  /********************************************************************
  Convert Cookie Map into String. Output: Flattened String

  @param {String} cookie_name - Cookie Name/Key
  @param {String} cookie_value - Cookie Value
  @param {Map} cookie_options - Cookie Options (Forward for Cookie Library)

  @return {String} - Serialized cookie as string
  *********************************************************************/
  serializeCookie: function(cookie_name, cookie_value, cookie_options){

    // Serialize Cookie
    return Lib.Cookie.serialize(cookie_name, cookie_value, cookie_options);

  },


  /********************************************************************
  Do not set SameSite None for incompatible browsers (Check useragent-agent)
  Ref: https://www.chromium.org/updates/same-site/incompatible-clients
  Ref: https://github.com/GoogleChromeLabs/samesite-examples/blob/cloudflare-worker/cloudflare-worker.md

  @param {String} useragent - user-agent of client browser

  @return {Boolean} is_incompatible - true if user-agent is of a browser known to be incompatible
  *********************************************************************/
  isSameSiteNoneIncompatible: function(useragent){

    // Known Webkit Browsers with SameSite Bug
    function hasWebKitSameSiteBug(useragent){

      return (
        isIosVersion(12, useragent) ||
        (
          isMacosxVersion(10, 14, useragent) &&
          ( isSafari(useragent) || isMacEmbeddedBrowser(useragent) )
        )
      );
    }


    // Known Browsers that drops unrecognized SameSite Value
    function dropsUnrecognizedSameSiteCookies(useragent) {

      if( isUcBrowser(useragent) ){
        return !isUcBrowserVersionAtLeast(12, 13, 2, useragent);
      }

      return (
        isChromiumBased(useragent) &&
        isChromiumVersionAtLeast(51, useragent) &&
        !isChromiumVersionAtLeast(67, useragent)
      );

    }


    // Regex parsing of User-Agent string. (See note above!)
    function isIosVersion(major, useragent) {
      const regex = /\(iP.+; CPU .*OS (\d+)[_\d]*.*\) AppleWebKit\//g;
      // Extract digits from first capturing group.
      const match = useragent.match(regex);
      return match && match[0] == major;
    }

    function isMacosxVersion(major, minor, useragent) {
      const regex = /\(Macintosh;.*Mac OS X (\d+)_(\d+)[_\d]*.*\) AppleWebKit\//g;
      // Extract digits from first and second capturing groups.
      const match = useragent.match(regex);
      return match && (match[0] == major) &&
        (match[1] == minor);
    }

    function isSafari(useragent) {
      const safari_regex = /Version\/.* Safari\//g;
      return safari_regex.test(useragent) &&
        !isChromiumBased(useragent);
    }

    function isMacEmbeddedBrowser(useragent) {
      const regex = /^Mozilla\/[\.\d]+ \(Macintosh;.*Mac OS X [_\d]+\) AppleWebKit\/[\.\d]+ \(KHTML, like Gecko\)$/g;
      return regex.test(useragent);
    }

    function isChromiumBased(useragent) {
      const regex = /Chrom(e|ium)/g;
      return regex.test(useragent);
    }

    function isChromiumVersionAtLeast(major, useragent) {
      const regex = /Chrom[^ \/]+\/(\d+)[\.\d]* /g;
      // Extract digits from first capturing group.
      const version = useragent.match(regex)[0];
      return version >= major;
    }

    function isUcBrowser(useragent) {
      const regex = /UCBrowser\//g;
      return regex.test(useragent);
    }

    function isUcBrowserVersionAtLeast(major, minor, build, useragent) {
      const regex = /UCBrowser\/(\d+)\.(\d+)\.(\d+)[\.\d]* /g;
      // Extract digits from three capturing groups.
      const major_version = useragent.match(regex)[0];
      const minor_version = useragent.match(regex)[1];
      const build_version = useragent.match(regex)[2];

      if (major_version != major) {
        return major_version > major;
      }

      if (minor_version != minor) {
        return minor_version > minor;
      }

      return build_version >= build;
    }



    // Check if incompatible browser
    return (
      hasWebKitSameSiteBug(useragent) ||
      dropsUnrecognizedSameSiteCookies(useragent)
    );

  },

};/////////////////////////Private Functions END///////////////////////////////
