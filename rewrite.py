from mitmproxy import http
from mitmproxy import ctx
from mitmutils import utils
import re, json

HOME_DIR = './'
DATA_DIR = HOME_DIR + 'responses/'
ROUTER_FILE = HOME_DIR + 'rewrite-router.yaml'

def request(flow: http.HTTPFlow) -> None:
    routers = utils.readFile(ROUTER_FILE)
    url = flow.request.url
    ctx.log.info(url)

    if routers is not None:
      for patternURL, jsonfilename in routers.items():
          if re.match(patternURL, url) is not None:
              jsonfile = DATA_DIR + str(jsonfilename) + '.json'
              data = utils.readFile(jsonfile)
              if data is not None:
                  status = int(data['status'])
                  try:
                      content = json.dumps(data['content'])
                  except:
                      content = ''
                  header = data['header']
                  flow.response = http.HTTPResponse.make(status, content, header)

