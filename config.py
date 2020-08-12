db = {
        'user' : 'root',
        'password' : 'root1234',
        'host' : 'python-backend-test.cmtozdongjgt.ap-northeast-2.rds.amazonaws.com',
        'port' : 3306,
        'database' : 'miniter'
        }

DB_URL = f"mysql+mysqlconnector://{db['user']}:{db['password']}@{db['host']}:{db['port']}/{db['database']}?charset=utf8"
JWT_SECRET_KEY = 'secrete'

test_db = {
        'user' : 'root',
        'password' : 'root12',
        'host' : 'localhost',
        'port' : 3306,
        'database' : 'miniter1'
        }

test_config = {
        'DB_URL' : f"mysql+mysqlconnector://{test_db['user']}:{test_db['password']}@{test_db['host']}:{test_db['port']}/{test_db['database']}?charset=utf8"
        }
