var express = require('express');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var pg = require('pg');
var decode = require('salesforce-signed-request');
var app = express();
var consumerSecret = process.env.CONSUMER_SECRET;
app.set('port', process.env.PORT || 5000);

app.use(express.static('public'));
app.use(bodyParser.json());

app.post('/update', function(req, res) {
    pg.connect(process.env.DATABASE_URL, function (err, conn, done) {
        // watch for any connect issues
        if (err) console.log(err);
        conn.query(
            'UPDATE salesforce.Installation__c SET Status__c = $1 WHERE  Serial_Number__c = $2 ',
            [req.body.status.trim(), req.body.sno.trim()],
            function(err, result) {
                if (err != null || result.rowCount == 0) {
                  conn.query('INSERT INTO salesforce.Installation__c (Status__c, Serial_Number__c) VALUES ($1, $2)',
                  [req.body.status.trim(), req.body.sno.trim()],
                  function(err, result) {
                    done();
                    if (err) {
                        res.status(400).json({error: err.message});
                    }
                    else {
                        // this will still cause jquery to display 'Record updated!'
                        // eventhough it was inserted
                        res.json(result);
                    }
                  });
                }
                else {
                    done();
                    res.json(result);
                }
            }
        );
    });
});
app.post('/canvas', function(req, res) {
    console.log('--Inside signed request--');
    try {
        //console.log(req.params['signed_request']);
        //console.log(req.form);
        //console.log(req.body);
        //console.log(req.headers);
        //console.log(res);
        //console.log(res.signed_request);
        //console.log(JSON.stringify(res.body));
        //console.log(JSON.stringify(req.body));
        //var canvasRequest = verifyAndDecode(req.body.signed_request, consumerSecret);
        
      } catch (ex) {
        console.log('Exception!');
        console.log(ex);
      }
      return res.redirect('https://testabbinstallations.herokuapp.com');
     //res.sendfile('/index.html');
});
function verifyAndDecode(input, secret){
    console.log(input);
    if (!input || input.indexOf('.') <= 0) {
	    throw 'Input doesn\'t look like a signed request';
	}
	var split = input.split('.', 2);
    var encodedSig = split[0];
    var encodedEnvelope = split[1];

    // Deserialize the json body
    var json_envelope = new Buffer(encodedEnvelope,'base64').toString('utf8');
    var algorithm;
    var canvasRequest;
    try {
        canvasRequest = JSON.parse(json_envelope);
        algorithm = canvasRequest.algorithm ? "HMACSHA256" : canvasRequest.algorithm;
    } catch (e) {
        throw 'Error deserializing JSON: '+ e;
    }

    // check algorithm - not relevant to error
    if (!algorithm || algorithm.toUpperCase() !== 'HMACSHA256') {
        throw 'Unknown algorithm '+algorithm+'. Expected HMACSHA256';
    }

	expectedSig = crypto.createHmac('sha256', secret).update(split[1]).digest('base64');
    if (encodedSig !== expectedSig) {
       throw 'Bad signed JSON Signature!';
    }


	return canvasRequest;

}
app.listen(app.get('port'), function () {
    console.log('Express server listening on port ' + app.get('port'));
});
