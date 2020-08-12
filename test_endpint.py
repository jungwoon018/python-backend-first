from . import config
import pytest
import json
import bcrypt
from sqlalchemy import create_engine, text
from .app import create_app

database = create_engine(config.test_config['DB_URL'], encoding='utf-8', max_overflow = 0)

@pytest.fixture
def api():
    app = create_app(config.test_config)
    app.config['TEST'] = True
    api = app.test_client()

    return api

def test_ping(api):
    resp = api.get('/ping')
    assert b'pong' in resp.data

def test_tweet(api):
    #테스트 사용자 생성
    new_user = {
            'email' : 'jungwoon018@naver.com',
            'password' : '1234',
            'name' : 'Son',
            'profile' : 'test profile'
            }

    resp = api.post(
            '/sign_up',
            data = json.dumps(new_user),
            content_type = 'application/json'
            )

    assert resp.status_code == 200

    #get the id of the new user

    resp_json = json.loads(resp.data.decode('utf-8'))
    new_user_id = resp_json['id']

    #로그인
    resp = api.post(
            '/login',
            data = json.dumps({'email' : 'jungwoon018@naver.com', 'password' : '1234'}),
            content_type = 'application/json'
            )
    resp_json = json.loads(resp.data.decode('utf-8'))
    access_token = resp_json['access_token']

    #tweet
    resp = api.post(
            '/tweet',
            data = json.dumps({'tweet' : "Hello World"}),
            content_type = 'application/json',
            headers = {'Authorization' : access_token}
            )
    assert resp.status_code == 200

    #tweet 확인
    resp = api.get(f'/timeline/{new_user_id}')
    tweets = json.loads(resp.data.decode('utf-8'))

    assert resp.status_code == 200
    assert tweets == {
            'user_id' : 6,
            'timeline' : [
                {
                    'user_id' : 6,
                    'tweet' : "Hello World"
                }
            ]
        }


