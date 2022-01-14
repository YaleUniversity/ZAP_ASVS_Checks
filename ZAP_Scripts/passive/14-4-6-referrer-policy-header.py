"""

Script testing 14.4.6 control from OWASP ASVS 4.0:
'Verify that a suitable Referrer-Policy header is included to avoid exposing
sensitive information in the URL through the Referer header to untrusted
parties.'

The script will raise an alert if 'Referrer-Policy' header is not present or does not contain 'strict-origin-when-cross-origin option'.

"""

def scan(ps, msg, src):

  header = str(msg.getResponseHeader().getHeader("Referrer-Policy"))

  alertRisk= 0
  alertConfidence = 1
  alertTitle = "14.4.6 Verify that a suitable Referrer-Policy header is included."
  alertDescription = "Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy"
  alertSolution = "Add 'Referrer-Policy: strict-origin-when-cross-origin' header when sending HTTP response."
  alertEvidence = "" 
  cweID = 116
  wascID = 0
  
  if (header.lower() not in ["strict-origin-when-cross-origin"]):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
