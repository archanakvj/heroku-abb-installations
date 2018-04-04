var express = require('express');
var bodyParser = require('body-parser');
var pg = require('pg');
var decode = require('signed-request');
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
app.post('/signedrequest', function(req, res) {
    // You could save this information in the user session if needed
    var signedRequest = decode(req.body.signed_request, consumerSecret);

});
app.listen(app.get('port'), function () {
    console.log('Express server listening on port ' + app.get('port'));
});
