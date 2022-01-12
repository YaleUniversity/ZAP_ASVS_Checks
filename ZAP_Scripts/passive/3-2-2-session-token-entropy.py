"""

Script testing 3.2.2 control from OWASP ASVS 4.0:
'Verify that session tokens possess at least 64 bits of entropy.'

A session token with 64 bits of entropy must be at least 128 bits in length. The script will raise an alert if a session token is less than 128 bits (22 Base-64 characters).

"""

def scan(ps, msg, src):

  cookies = msg.getResponseHeader().getHttpCookies()

  alertRisk= 0
  alertConfidence = 1
  alertTitle = "3.2.2 Verify that session tokens possess at least 64 bits of entropy."
  alertDescription = "Session identifiers should be at least 128 bits long to prevent brute-force session guessing attacks."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length"
  alertSolution = "Ensure any session token is at least 128 bits long."
  alertEvidence = "" 
  cweID = 614
  wascID = 0
  
  for c in cookies:
    if (len(c) < 22):
      alertEvidence = c
      ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
