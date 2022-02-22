"""

Script testing 5.2.7 control from OWASP ASVS 4.0:
'Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, 
especially as they relate to XSS resulting from inline scripts, and foreignObject.'


This script will inject an SVG XSS payload to see if it is returned in the response body without being sanatized or escaped.

"""

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "5.2.7 Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content."
  alertDescription = "Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, especially as they relate to XSS resulting from inline scripts, and foreignObject."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = ""
  alertSolution = ""
  alertEvidence = "" 
  cweID = 159
  wascID = 0
 
  #SVG payload
  attack = '<svg xmlns="http://www.w3.org/1999/svg"> <script> alert(1) </script> </svg>'

  #clone message
  msg = msg.cloneRequest();
  
  # setParam (message, parameterName, newValue)
  sas.setParam(msg, param, attack);

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);


  #check if attack payload is reflected back in the response body, if so raise alert
  try: # use try/except to avoid parsing issues from invalid response bodies 
    body = str(msg.getResponseBody())
    if (attack in body):
      alertAttack = attack
      alertEvidence = attack + " in Response Body"
      sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
  except:
    pass

