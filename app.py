from flask import Flask, jsonify, request, Response, current_app, g
from sqlalchemy import create_engine, text
from functools import wraps #decorator 함수를 만들기 위해 wraps decorator함수를 사용한다.
from datetime import datetime, timedelta #datetime함수 사용하기 위한 모듈
from flask_cors import CORS
import bcrypt #bcrypt 모듈 입포트
import jwt #jwt 모듈 임포트


#유저 정보를 가져오는 함수
def get_user_info(user_id):
    user = current_app.database.execute(text("""
        SELECT
            id,
            name,
            email,
            profile
        FROM users
        WHERE id = :user_id
    """), {
        'user_id' : user_id
    }).fetchone()

    return {
            'id' : user['id'],
            'name' : user['name'],
            'email' : user['email'],
            'profile' : user['profile']
            } if user else None

#access token 인증 decorator 함수
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #http header에서 Authorization을 받아온다(토큰 정보)
        access_token = request.headers.get('Authorization')
        #토큰 정보가 없으면 401 에러를 전송
        if access_token is not None:
            #토큰 정보를 디코드 시킨다.
            try:
                payload = jwt.decode(access_token, 'secret', 'HS256')
            except jwt.InvalidTokenError:
                payload = None

            #토큰 정보가 디코드에 실패하면 401에러 메세지를 보낸다.
            if payload is None: return Reponse(status=401)
            #
            user_id = payload['user_id']
            g.user_id = user_id
            g.user = get_user_info(user_id) if user_id else None
        else:
            return Response(status = 401)

        return f(*args, **kwargs)
    return decorated_function

def create_app(test_config = None):
    app = Flask(__name__)

    CORS(app)

    if test_config is None:
        app.config.from_pyfile("config.py")
    else:
        app.config.update(test_config)

    database = create_engine(app.config['DB_URL'], encoding = 'utf-8', max_overflow = 0)
    app.database = database

    @app.route("/ping", methods=['GET'])
    def ping():
        return "pong"

    @app.route("/sign_up", methods=['POST'])
    def sign_up():
        new_user = request.json
        #password 암호화
        new_user['password'] = bcrypt.hashpw(
            new_user['password'].encode('UTF-8'),
            bcrypt.gensalt()
        )
        #데이터 베이스에 정보 저장
        new_user_id = app.database.execute(text("""
            INSERT INTO users(
                name,
                email,
                profile,
                hashed_password
            ) VALUES (
                :name,
                :email,
                :profile,
                :password
            )
            """), new_user).lastrowid

        row = app.database.execute(text("""
            SELECT
                id,
                name,
                email,
                profile
            FROM users
            where id = :user_id
            """), {
                'user_id' : new_user_id
            }).fetchone()

        created_user = {
            'id' : row['id'],
            'name' : row['name'],
            'email' : row['email'],
            'profile' : row['profile']
        } if row else None

        return jsonify(created_user)

    @app.route('/login', methods=['POST'])
    def login():
        credential = request.json
        #http요청으로 전송된 json body에서 사용자의 이메일을 읽어 들인다.
        email = credential['email']
        #http 요청으로 전송된 json body에서 사용자의 비밀번호를 읽어 들인다.
        password = credential['password']
        #데이터 베이스에 저장된 암호와 아이디를 읽어들인다.
        row = database.execute(text("""
            SELECT
                id,
                hashed_password
            FROM users
            WHERE email = :email
        """), {'email' : email}).fetchone()
        #임호화된 비밀번호와 사용자가 입력한 비밀번호가 같은지 확인한다.
        #row가 None이면 사용자가 없는것임으로 권한을 주지  않는다.
        if row and bcrypt.checkpw(password.encode('UTF-8'), row['hashed_password'].encode('UTF-8')):
            user_id = row['id']
            payload = {
                    'user_id' : user_id,#id를 jwt payload에 저장
                    'exp' : datetime.utcnow() + timedelta(seconds = 60 * 60 * 24)#인증 유효 시간 설정
                    }
            #jwt인코더를 이용해 토큰 생성(jwt 생성)
            #첫번째인자는 payload, 두번째 인자는 signature부분을 암호화할 때 사용할 비밀 키 지정
            #세번째 인자는 signature 부분을 암호화할 때 사용할 암호 알고리즘을 지정한다.
            app.config['JWT_SECRET_KEY'] = 'secret'
            token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], 'HS256')

            return jsonify({
                'access_token' : token.decode('UTF-8')
                })
        else:
            return '', 401

    @app.route('/tweet', methods=['POST'])
    @login_required
    def tweet():
        user_tweet = request.json
        user_tweet['id'] = g.user_id
        tweet = user_tweet['tweet']

        if len(tweet) > 300:
            return '300자를 초과했습니다.', 400

        app.database.execute(text("""
            INSERT INTO tweets(
                user_id,
                tweet
            ) VALUES (
                :id,
                :tweet
            )
        """), {
            'id' : int(user_tweet['id']),
            'tweet' : user_tweet['tweet']
        })

        return '', 200

    @app.route('/follow', methods=['POST'])
    @login_required
    def follow():
        user_follow = request.json

        app.database.execute(text("""
            INSERT INTO users_follow_list(
                user_id,
                follow_user_id
            ) VALUES (
                :id,
                :follow
            )
            """), {
                'id' : int(user_follow['id']),
                'follow' : user_follow['follow']
            })

        return '', 200

    @app.route('/follow_list/<int:user_id>', methods=['GET'])
    @login_required
    def follow_list(user_id):
        rows = app.database.execute(text("""
            SELECT
                follow_user_id
            FROM users_follow_list
            WHERE user_id = :id
        """), {'id' : user_id}).fetchall()

        follow_list = [ row['follow_user_id'] for row in rows ]

        return jsonify({
            'user_id' : user_id,
            'follow_id' : follow_list
        })

    @app.route('/unfollow', methods=['POST'])
    def unfollow():
        unfollow_id = request.json

        app.database.execute(text("""
            DELETE
            FROM users_follow_list
            WHERE user_id = :id AND follow_user_id = :follow
        """), unfollow_id)

        return '', 200

    @app.route('/timeline/<int:user_id>', methods=['GET'])
    def timeline(user_id):
        rows = app.database.execute(text("""
            SELECT
                t.user_id,
                t.tweet
            FROM tweets t
            LEFT JOIN users_follow_list ufl
            ON ufl.user_id = :user_id
            WHERE t.user_id = :user_id
            OR t.user_id = ufl.follow_user_id
        """), {
            'user_id' : user_id
        }).fetchall()

        timeline = [{
            'user_id' : row['user_id'],
            'tweet' : row['tweet']
        } for row in rows]

        return jsonify({
            'user_id' : user_id,
            'timeline' : timeline
        })

    return app
