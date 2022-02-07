"""

Script testing 5.2.4 control from OWASP ASVS 4.0:
'Verify that the application avoids the use of eval() or other dynamic code
execution features. Where there is no alternative, any user input being
included must be sanitized or sandboxed before being executed.'

The script will raise an alert if 'eval' or 'include' is present in the response body.

"""

def scan(ps, msg, src):



  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "5.2.4. Verify that the application avoids the use of eval() or other dynamic code execution features."
  alertDescription = "Verify that the application avoids the use of eval() or other dynamic code execution features. Where there is no alternative, any user input being included must be sanitized or sandboxed before being executed."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20Injection" + "/n" "https://owasp.org/www-community/attacks/Code_Injection"
  alertSolution = "Ensure the use of eval() or include() do not expose the application to dynamic code execution injection."
  alertEvidence = "" 
  cweID = 95
  wascID = 0

  try:
    #get response body
    body = str(msg.getResponseBody())
  
    #if 'eval' or 'include' is in response body, raise alert
    if (body != "None" and ("eval(" in body.lower() or "include(" in body.lower())):
      ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
  except:
    pass
