"""

Script testing 3.1.1 control from OWASP ASVS 4.0:
'Verify the application never reveals session tokens in URL
parameters.'

The script will raise an alert if the following are found in the URL:
	1. strings: "PHPSESSID", "JSESSIONID", "CFID", "CFTOKEN", "ASP.NET_SESSIONID", "ID", "COOKIE", "JWT", "SESSION"
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
  alertTitle = "3.1.1 Verify the application never reveals session tokens in URL parameters."
  alertDescription = "Verify the application never reveals session tokens in URL parameters."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-name-fingerprinting"
  alertSolution = "Remove session tokens from URL: " + url
  alertEvidence = url 
  cweID = 598
  wascID = 0
  
  tokens = ["PHPSESSID", "JSESSIONID", "CFID", "CFTOKEN", "ASP.NET_SESSIONID", "ID", "COOKIE", "JWT", "SESSION"]

  app_token = getToken(msg)
  if (app_token is not None):
    tokens.append(app_token.upper())
  
  for t in tokens:
    if (t in url.upper()):
      alertParam = t
      ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
