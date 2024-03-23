// Info: Test Cases
'use strict';

// Shared Dependencies
var Lib = {};

// Set Configrations
const money_config = {
  'HTTP_PROVIDER': 'aws'
};

// Dependencies
Lib.Utils = require('js-helper-utils');
Lib.Debug = require('js-helper-debug')(Lib);
Lib.Crypto = require('js-helper-crypto-nodejs')(Lib);
Lib.Instance = require('js-helper-instance')(Lib);
const HttpHandler = require('js-helper-http-handler')(Lib);


////////////////////////////SIMILUTATIONS//////////////////////////////////////

// function to simulate http-gateway callback
var fake_httpGatewayCallback = function(error, return_response){

  if(error){
    Lib.Debug.logErrorForResearch(error);
  }

  Lib.Debug.log('return_response', return_response);

}

///////////////////////////////////////////////////////////////////////////////


/////////////////////////////STAGE SETUP///////////////////////////////////////

// Initialize 'instance'
var instance = Lib.Instance.initialize();

// Load dummy event data
var request_data_get_v1 = require('./dummy_data/event-http-get-v1.json');
var request_data_post_v2 = require('./dummy_data/event-http-post-v1.json');
var request_data_get_v1 = require('./dummy_data/event-http-get-v2.json');
var request_data_post_v2 = require('./dummy_data/event-http-post-v2.json');

// Load dummy context data
var request_context = null;

///////////////////////////////////////////////////////////////////////////////


/////////////////////////////////TESTS/////////////////////////////////////////

// Test .isHttpInstance() function (Before initalization of HTTP)
Lib.Debug.log(
  'isHttpInstance() before HTTP initalization: ',
  HttpHandler.isHttpInstance(instance)
);


// Test .initHttpRequestData() function
//HttpHandler.initHttpRequestData(instance, request_data_get_v1, request_context, fake_httpGatewayCallback, 'aws');
HttpHandler.initHttpRequestData(instance, request_data_post_v2, request_context, fake_httpGatewayCallback, 'aws');
Lib.Debug.log(
  'initHttpRequestData() -> instance: ',
  instance
);


// Test .isHttpInstance() function (after initalization of HTTP)
Lib.Debug.log(
  'isHttpInstance() after HTTP initalization: ',
  HttpHandler.isHttpInstance(instance)
);


// Test .getHttpRequestOrigin() function
Lib.Debug.log(
  'getHttpRequestOrigin():',
  HttpHandler.getHttpRequestOrigin(instance)
);


//Set Cookie
HttpHandler.setCookie(
  instance,
  'custom_cookie_name',
  'custom_cookie_value',
  31536000 // expire after 365 days
);

// Test .returnHttpResponseToGateway() function
const headers = {
  'custom_header_key': 'some custom header value'
};
const body = {
  'key1': 'value1',
  'key2': true,
  'key3': 456789,
};

HttpHandler.returnHttpResponseToGateway(
  instance,
  200,
  headers,
  body
);


// Test .returnHttpStatusToGateway() function
HttpHandler.returnHttpStatusToGateway(
  instance,
  'not_modified'
);


// Test .returnHttpRedirectToGateway() function
HttpHandler.returnHttpRedirectToGateway(
  instance,
  '/somepage'
);


// Test .returnHttpRedirect404ToGateway() function
HttpHandler.returnHttpRedirect404ToGateway(
  instance
);


// Test .setArgsFromHttpRequestData() function
var err = { code: 123, message: "intentional error" }
var json_translator = function(json){
  return {
    'x': json['a'],
    'y': json['b']
  }
};
var invalidator = function(json){
  return [
    Lib.Utils.error( err, 'dummy_context' ),
    Lib.Utils.error( err )
  ]
};
var args_get = HttpHandler.setArgsFromHttpRequestData(instance, [

  { // Param 1
    'method'        : 'GET',
    'name'          : 'get_key1',
    'rename'        : 'get_key1',
    'required'      : true,
    'trim'          : true
  },

  { // Param 2
    'method'        : 'GET',
    'name'          : 'get_key2',
    'rename'        : 'get_key2',
    'required'      : false,
    'required'      : false,
    'trim'          : true
  },

  { // Param 3
    'method'        : 'GET',
    'name'          : 'get_keyX',
    'rename'        : 'get_keyX',
    'required'      : false,
    'default'       : 'I am default value',
    'trim'          : true
  }

]);

var args_post = HttpHandler.setArgsFromHttpRequestData(instance, [

  { // Param 1
    'method'        : 'POST',
    'name'          : 'post_key1',
    'rename'        : 'post_key1',
    'required'      : true,
    'trim'          : true
  },

  { // Param 2
    'method'        : 'POST',
    'name'          : 'post_key2',
    'rename'        : 'post_key2',
    'required'      : false,
    'required'      : false,
    'trim'          : true
  },

  { // Param 3
    'method'          : 'POST',
    'name'            : 'post_key3',
    'rename'          : 'post_key3',
    'required'        : true,
    'trim'            : true,
    'is_json'         : true,
    'json_func'       : json_translator,
    'invalidate_func' : invalidator
  },

  { // Param 4
    'method'        : 'POST',
    'name'          : 'post_keyX',
    'rename'        : 'post_keyX',
    'required'      : false,
    'default'       : 'I am default value',
    'trim'          : true
  },

  { // Param 4
    'method'        : 'FIXED',
    'rename'        : 'custom_1',
    'value'         : 'hello custom'
  }

]);

Lib.Debug.log( // Output: [false, false]
  'setArgsFromHttpRequestData(args_get):',
  args_get
);
Lib.Debug.log( // Output: [..., false]
  'setArgsFromHttpRequestData(args_post):',
  args_post
);




// Test .getUrlParts()
Lib.Debug.log( // Return: {...}
  'getUrlParts("http://www.abc.example.co.us:8080")',
  HttpHandler.getUrlParts('http://www.abc.example.co.us:8080')
  //HttpHandler.getUrlParts('10.0.0.1:8080')
);

///////////////////////////////////////////////////////////////////////////////
