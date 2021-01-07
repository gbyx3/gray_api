import requests
import settings
import json
import datetime
import bottle
import redis
import logging

app = application = bottle.default_app()
logger = logging.getLogger("gray_api")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(settings.log_file)
handler.setFormatter(formatter)
logger.addHandler(handler)

debug = settings.debug

def apicheck(fn):
  def _wrap(*args, **kwargs):
    try:
      provided_api_key = bottle.request.headers['api-key']
    except:
      provided_api_key = ''
    try:
      for api_key in settings.api_keys:
        if provided_api_key == api_key['api-key']:
          if bottle.request.path in api_key['allowed']:
            logger.info('api-key user: {} logged: {}, remote ip: {}'.format(api_key['username'], bottle.request.path, bottle.request.environ.get('REMOTE_ADDR')))
            return fn(*args, **kwargs)
        if bottle.request.environ.get('REMOTE_ADDR') in api_key['whitelist']:
          if bottle.request.path in api_key['allowed']:
            logger.info('whitelisted user: {} logged: {}, remote ip: {}'.format(api_key['username'], bottle.request.path, bottle.request.environ.get('REMOTE_ADDR')))
            return fn(*args, **kwargs)
    except Exception as e:
      logger.info('Exception was: {}'.format(e))
      bottle.response.status = 401
      return {"result":"failed","message":"Something went wrong, exiting..."}
     
    logger.info('{} api auth failed for {}'.format(bottle.request.path, bottle.request.environ.get('HTTP_X_FORWARDED_FOR')))
    bottle.response.status = 401
    return {"result":"failed","message":"api-key is not valid here"}
  return _wrap


def update_redis(key, db=0, data=datetime.datetime.now().strftime("%Y-%b-%d %H:%M")):
  '''
  Update / add item to redis
  :param key: redis key
  :type key: str
  :param db: redis index
  :type db: int
  :param data: data to store in key
  :type data: str
  :return: True / False
  :rtype: bool
  '''
  r = redis.StrictRedis(settings.redis_host, port=6379, db=db, password=settings.redis_auth)
  h = r.set(key, data)
  return h


@bottle.get('/gray_api/auth')
@apicheck
def auth():
    return {'status_code':200, 'message':'apicheck passed'}


@bottle.get('/gray_api/ipv4list')
def ipv4list():
  '''
  Return all ip's in a specific database index
  '''
  r = redis.StrictRedis(settings.redis_host, port=6379, db=1, password=settings.redis_auth)
  pattern = '*'
  bottle.response.status = 200
  return bottle.template('ip_list.html', blocklist=r.keys(pattern), your_location=settings.your_location)


@bottle.post('/gray_api/redis_blocklist')
@apicheck
def redis_blocklist():
  '''
  Add ip to redis index
  '''
  try:
    byte = bottle.request.body
    data = json.loads(byte.read().decode('UTF-8'))
    if debug:
      logger.info(data)
  except Exception as e:
    logger.exception('Failed to read body')
    bottle.response.status = 400
    return {'status':400, 'message':'Wrong input parameters'}

  if data['event_definition_id'] == 'this-is-a-test-notification':
    bottle.response.status = 201
    return 

  for message in data['backlog']:
    try:
      ssh_invalid_user_ip = message['fields']['ssh_invalid_user_ip']
    except:
      logger.debug('Failed to read input parameters')
      bottle.response.status = 400
      return {'status':400, 'message':'Wrong input parameters'}
    try:
      update_redis(ssh_invalid_user_ip, db=settings.redis_index)
      logger.debug('Added {} to redis'.format(ssh_invalid_user_ip,))
    except:
      logger.exception('Failed to add IP to redis...')
      bottle.response.status = 500
      return {'status_code':500, 'message':'Failed to add ip to redis'}

  bottle.response.status = 200
  return {'status_code':200, 'message':'Successfully added ip to redis'}


if __name__ == '__main__':
  bottle.run(host='0.0.0.0', port=8080, debug=True, reloader=True)
