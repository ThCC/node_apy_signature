node_apy_signature - ApySignature
=================================
Javascript implementation of the Python Signature Library (https://github.com/erickponce/apysignature)


Installation
------------
    
    npm install apysignature 

Examples
--------

    var _request = require('request');
    var signature = require('./signature');
    var querystring = require("querystring");
    
    var params = {some: 'parameters'};
    var signedReq = new signature.Request('post', '/api/thing', params);
    var token = new signature.Token('my_key', 'my_secret');
    token.sign(signedReq);
    var authDict = signedReq.getAuthDict();
    var url = 'localhost:80' + '/api/thing?' + querystring.stringify(authDict);
    
    _request({url: url, method: 'POST', json: true, body: params},
        function (error, response, body) {
            console.info('Response', response, 'Error', error, 'Body', body);
        }
    );

Copyright
---------

Copyright (c) 2016 Erick Ponce. See LICENSE for details.