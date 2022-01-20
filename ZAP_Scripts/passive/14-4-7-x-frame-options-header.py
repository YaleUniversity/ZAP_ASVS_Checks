"""

Script testing 14.4.7 control from OWASP ASVS 4.0:
'Verify that the content of a web application cannot be embedded in a third-
party site by default and that embedding of the exact resources is only
allowed where necessary by using suitable Content-Security-Policy: frame-
ancestors and X-Frame-Options response headers.'

The script will raise an alert if 
	1. X-Frame-Options: deny or X-Frame-Options: sameorigin
	2. Content-Security-Policy: frame-ancestors ‘none’ or Content-Security-Policy: frame-ancestors
is not present. 

"""

def scan(ps, msg, src):

  #find "X-Frame-Options" and "Content-Security-Policy" headers
  header_xframe = str(msg.getResponseHeader().getHeader("X-Frame-Options"))
  header_csp = str(msg.getResponseHeader().getHeader("Content-Security-Policy"))

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "14.4.7 Verify that the content of a web application cannot be embedded in a third- party site."
  alertDescription = "Verify that the content of a web application cannot be embedded in a third- party site by default and that embedding of the exact resources is only allowed where necessary by using suitable Content-Security-Policy: frame-ancestors and X-Frame-Options response headers."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options" + "/n" + "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-security-policy"
  solutions = ["Add proper X-Frame-Options header to HTTP responses (deny or sameorigin).", "Add proper Content-Security-Policy: frame-ancestors header to HTTP responses."]
  alertSolution = ""
  alertEvidence = "" 
  cweID = 1021
  wascID = 0

  #if "X-Frame-Options" is not set to "sameorigin" or "deny", change alert solution
  if (header_xframe.lower() not in ["sameorigin", "deny"]):
    alertSolution = solutions[0]

  #if "Content-Security-Policy" is not set to "frame-ancestors", change alert solution
  elif (header_csp.lower() not in ["frame-ancestors"]):
    alertSolution = solutions[1]

  #if alert solution has changed, raise alert
  if (alertSolution != ""):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
