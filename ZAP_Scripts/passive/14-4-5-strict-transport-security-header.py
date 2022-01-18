"""

Script testing 14.4.5 control from OWASP ASVS 4.0:
'14.4.5 Verify that a Strict-Transport-Security header is included on all responses
and for all subdomains, such as Strict-Transport-Security: max-
age=15724800; includeSubdomains.'

The script will raise an alert if 'Strict-Transport-Security' header is not present. 

"""

def scan(ps, msg, src):

  header = str(msg.getResponseHeader().getHeader("Strict-Transport-Security"))

  alertRisk= 0
  alertConfidence = 1
  alertTitle = "14.4.5 Verify that a Strict-Transport-Security header is included on all responses."
  alertDescription = "Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
  alertSolution = "Add 'Strict-Transport-Security' header to all HTTP repsponses."
  alertEvidence = "" 
  cweID = 523
  wascID = 0
  
  if (header is None):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
