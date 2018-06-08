import connexion
from non_repudiation import sign_header, hash_body, verify
from cert import create_key, cert_to_string
create_key("server")
create_key("client")
import time

app = connexion.FlaskApp(__name__, specification_dir='swagger/',
                         arguments={'global': 'global_value'})
app.add_api('my_api.yaml', arguments={'api_local': 'local_value'})

# http://connexion.readthedocs.io/en/latest/routing.html


@app.app.after_request
def add_non_repudiation(response):
    with open('server.pem') as fh:
        x5c = cert_to_string(fh.read())
    non_repudiation = {
        'iss': 'ipa/oou',
        'aud': 'ipa/oou',
        'iat': int(time.time()),
        'exp': int(time.time() + 10),
        'jti': 'the header id',
        'sub': 'the message id',
        'date': '2018-01-01T12:00:00Z',
        'b_hash': hash_body(response.data),
        'x5c': x5c,
    }
    h = sign_header(fpath="server.key", claim=non_repudiation)
    if not response.headers:
        response.headers = {}
    response.headers['Non-Repudiation'] = h
    return response


@app.app.before_request
def check_non_repudiation():
    h = connexion.request.headers.get('Non-Repudiation')
    if not h:
        return

    verify("client.pem", h)


app.run(port=8080)
