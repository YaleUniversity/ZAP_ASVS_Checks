"""

Script testing 14.4.3 control from OWASP ASVS 4.0:
'Verify that a Content Security Policy (CSP) response header is in place that
helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript
injection vulnerabilities.'

The script will raise an alert if:
	1. There is no Content-Security-Policy or Content-Security-Policy-Report-Only header
	2. X-Content-Security-Policy or X-WebKit-CSP is used 

"""
#return valid header from ["Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Content-Security-Policy", "X-WebKit-CSP"]
def findHeaderType(msg):
  headers = ["Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Content-Security-Policy", "X-WebKit-CSP"]
  headerType = ""
  for h in headers:
    msg_header = str(msg.getResponseHeader().getHeader(h))
    if (msg_header != "None"):
      headerType = h
  return headerType

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "14.4.3 Verify that a Content Security Policy (CSP) response header is in place."
  alertDescription = "Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
  solutions = ["Add Content Security Policy (CSP) header in HTTP response.", "DO NOT use X-Content-Security-Policy or X-WebKit-CSP. Their implementations are obsolete (since Firefox 23, Chrome 25), limited, inconsistent, and incredibly buggy."]
  alertSolution = ""
  alertEvidence = "" 
  cweID = 1021
  wascID = 0

  headerType = findHeaderType(msg)
 
  #if header is "X-Content-Security-Policy" or "X-WebKit-CSP", change alert solution and evidence
  if (headerType in ["X-Content-Security-Policy", "X-WebKit-CSP"]):
    alertSolution = solutions[1]
    alertEvidence = str(msg.getResponseHeader().getHeader(headerType))
  #if there is no valid header, change alert solution
  elif (headerType == ""):
    alertSolution = solutions[0]
  
  #if alert solution has changed, raise alert
  if (alertSolution != ""):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
