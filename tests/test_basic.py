import pytest
import requests.auth
from requests.auth import HTTPDigestAuth
import re
import hashlib

reg=re.compile('(\w+)[:=] ?"?(\w+)"?') ## for parsing of WWW-Authenticate header

@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_postgres(service_client):
    ## initial request without Authorization
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    ## parse WWW-Authenticate header into dictionary of directives and values
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

    print(authentication_directives)
    assert 'realm' in authentication_directives
    assert 'nonce' in authentication_directives
    assert 'algorithm' in authentication_directives
    assert 'opaque' in authentication_directives
    assert 'qop' in authentication_directives

    ## now construct Authorization header sent from client
    chal = {'realm': authentication_directives["realm"], 
            'nonce': authentication_directives["nonce"],
            'algorithm': authentication_directives["algorithm"],
            'opaque': authentication_directives["opaque"],
            'qop': "auth"
            }
    ## response will be calculated below
    a = HTTPDigestAuth("Mufasa", "Circle Of Life")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')
    ## now send request with constructed Authorization header
    print(auth_header)
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200
    assert response.content == b'Hello world, Dear User!\n'
 
    ## try to change some directives
    chal['realm'] = 'new_realm'
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401
    assert "WWW-Authenticate" in response.headers

    ## 
    chal['nonce'] = 'abracadabra'
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401
    assert "WWW-Authenticate" in response.headers

    ## 
    chal['opaque'] = '0d0120d0sdf0102030sdf020'
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': a.build_digest_header('GET', '/v1/hello')},
    )
    assert response.status == 401
    assert "WWW-Authenticate" in response.headers
