import connexion
from non_repudiation import create_key, sign_header, hash_body, verify

create_key("server")
create_key("client")

app = connexion.FlaskApp(__name__, specification_dir='swagger/',
                         arguments={'global': 'global_value'})
app.add_api('my_api.yaml', arguments={'api_local': 'local_value'})

# http://connexion.readthedocs.io/en/latest/routing.html


@app.app.after_request
def add_non_repudiation(response):
    h = sign_header(fpath="server.key", hdr={
                    'bh': hash_body(response.data)}, x5c=True)
    if not response.headers:
        response.headers = {}
    response.headers['Non-Repudiation'] = h
    return response


@app.app.before_request
def check_non_repudiation():
    h = connexion.request.headers.get('Non-Repudiation')
    if not h:
        return

    verify("client.pub", h)


app.run(port=8080)
