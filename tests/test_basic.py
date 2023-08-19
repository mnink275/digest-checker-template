import pytest
import requests.auth
from requests.auth import HTTPDigestAuth
import re
import hashlib

reg=re.compile('(\w+)[:=][\s"]?([^",]+)"?')

@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_postgres(service_client):
    ## initial request without Authorization
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    ## parse WWW-Authenticate header into dictionary of directives and values
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

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
    a = HTTPDigestAuth("username", "pswd")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')

    ## now send request with constructed Authorization header
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401 ## but username wasn't present in RcuMap

    ## we need to repeat request:
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

    assert 'realm' in authentication_directives
    assert 'nonce' in authentication_directives
    assert 'algorithm' in authentication_directives
    assert 'opaque' in authentication_directives
    assert 'qop' in authentication_directives

    chal = {'realm': authentication_directives["realm"], 
            'nonce': authentication_directives["nonce"],
            'algorithm': authentication_directives["algorithm"],
            'opaque': authentication_directives["opaque"],
            'qop': "auth"
            }

    a = HTTPDigestAuth("username", "pswd")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200 ## success

@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_postgres_wrong_data(service_client):
    ## initial request without Authorization
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    ## parse WWW-Authenticate header into dictionary of directives and values
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

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
    a = HTTPDigestAuth("username", "pswd")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')

    ## now send request with constructed Authorization header
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401 ## but username wasn't present in RcuMap

    ## we need to repeat request:
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

    assert 'realm' in authentication_directives
    assert 'nonce' in authentication_directives
    assert 'algorithm' in authentication_directives
    assert 'opaque' in authentication_directives
    assert 'qop' in authentication_directives

    chal = {'realm': authentication_directives["realm"], 
            'nonce': authentication_directives["nonce"],
            'algorithm': authentication_directives["algorithm"],
            'opaque': authentication_directives["opaque"],
            'qop': "auth"
            }

    a = HTTPDigestAuth("username", "WRONG-PASSWORD")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401

# @pytest.mark.pgsql('auth', files=['test_data.sql'])
# async def test_postgres_proxy(service_client):
#     ## initial request without Authorization
#     response = await service_client.get('/v1/hello')
#     assert response.status == 401

#     ## parse WWW-Authenticate header into dictionary of directives and values
#     authentication_header = response.headers["Proxy-Authenticate"]
#     authentication_directives = dict(reg.findall(authentication_header))

#     assert 'realm' in authentication_directives
#     assert 'nonce' in authentication_directives
#     assert 'algorithm' in authentication_directives
#     assert 'opaque' in authentication_directives
#     assert 'qop' in authentication_directives

#     ## now construct Authorization header sent from client
#     chal = {'realm': authentication_directives["realm"], 
#             'nonce': authentication_directives["nonce"],
#             'algorithm': authentication_directives["algorithm"],
#             'opaque': authentication_directives["opaque"],
#             'qop': "auth"
#             }

#     ## response will be calculated below
#     a = HTTPDigestAuth("username", "pswd")
#     a.init_per_thread_state()
#     a._thread_local.chal = chal
#     auth_header = a.build_digest_header('GET', '/v1/hello')

#     ## now send request with constructed Authorization header
#     response = await service_client.get(
#         '/v1/hello', headers={'Proxy-Authorization': auth_header},
#     )
#     assert response.status == 401 ## but username wasn't present in RcuMap

#     ## we need to repeat request:
#     authentication_header = response.headers["Proxy-Authenticate"]
#     authentication_directives = dict(reg.findall(authentication_header))

#     assert 'realm' in authentication_directives
#     assert 'nonce' in authentication_directives
#     assert 'algorithm' in authentication_directives
#     assert 'opaque' in authentication_directives
#     assert 'qop' in authentication_directives

#     chal = {'realm': authentication_directives["realm"], 
#             'nonce': authentication_directives["nonce"],
#             'algorithm': authentication_directives["algorithm"],
#             'opaque': authentication_directives["opaque"],
#             'qop': "auth"
#             }

#     a = HTTPDigestAuth("username", "pswd")
#     a.init_per_thread_state()
#     a._thread_local.chal = chal
#     auth_header = a.build_digest_header('GET', '/v1/hello')

#     response = await service_client.get(
#         '/v1/hello', headers={'Proxy-Authorization': auth_header},
#     )
#     assert response.status == 200 ## success

@pytest.mark.pgsql('auth', files=['test_data.sql'])
async def test_repeated_auth(service_client):
    ## initial request without Authorization
    response = await service_client.get('/v1/hello')
    assert response.status == 401

    ## parse WWW-Authenticate header into dictionary of directives and values
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

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
    a = HTTPDigestAuth("username", "pswd")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')

    ## now send request with constructed Authorization header
    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 401 ## but username wasn't present in RcuMap

    ## we need to repeat request:
    authentication_header = response.headers["WWW-Authenticate"]
    authentication_directives = dict(reg.findall(authentication_header))

    assert 'realm' in authentication_directives
    assert 'nonce' in authentication_directives
    assert 'algorithm' in authentication_directives
    assert 'opaque' in authentication_directives
    assert 'qop' in authentication_directives

    chal = {'realm': authentication_directives["realm"], 
            'nonce': authentication_directives["nonce"],
            'algorithm': authentication_directives["algorithm"],
            'opaque': authentication_directives["opaque"],
            'qop': "auth"
            }

    a = HTTPDigestAuth("username", "pswd")
    a.init_per_thread_state()
    a._thread_local.chal = chal
    auth_header = a.build_digest_header('GET', '/v1/hello')

    response = await service_client.get(
        '/v1/hello', headers={'Authorization': auth_header},
    )
    assert response.status == 200 ## success