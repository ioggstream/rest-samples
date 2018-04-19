# Non-Repudiation API

A simple API appending a non-repudiation header containing a JWS-signed body hash.

To run the server, just:

        $ tox run & 
        $ curl -v http://localhost:8080/ping 	

And check the Non-Repudiation header.


