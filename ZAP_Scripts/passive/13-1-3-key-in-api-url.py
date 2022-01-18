"""

Script testing 13.1.3 control from OWASP ASVS 4.0:
'Verify API URLs do not expose sensitive information, such as the API key,
session tokens etc.'

Note: this script is almost identical to 3-1-1-token-in-url.py except, it contains strings related to api keys as well.

The script will raise an alert if the following are found in the URL:
	1. strings: "PHPSESSID", "JSESSIONID", "CFID", "CFTOKEN", "ASP.NET_SESSIONID", "ID", "COOKIE", "JWT", "SESSION", "KEY", "API"]
	2. actual token value from application (if sent)

"""
import ast

def getToken(msg):
  token = None
  try:
    body = str(msg.getResponseBody())
    token = ast.literal_eval(body).get('authentication').get('token')
  except:
    pass
  return token

def scan(ps, msg, src):

  alertRisk= 0
  alertConfidence = 1
  alertTitle = "13.1.3 Verify API URLs do not expose sensitive information."
  alertDescription = "Verify API URLs do not expose sensitive information, such as the API key, session tokens etc."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
  alertSolution = "Remove session tokens or api key from URL: " + url
  alertEvidence = url 
  cweID = 116
  wascID = 0
  
  tokens = ["PHPSESSID", "JSESSIONID", "CFID", "CFTOKEN", "ASP.NET_SESSIONID", "ID", "COOKIE", "JWT", "SESSION", "KEY", "API"]

  app_token = getToken(msg)
  if (app_token is not None):
    tokens.append(app_token.upper())
  
  for t in tokens:
    if (t in url.upper()):
      alertParam = t
      ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
