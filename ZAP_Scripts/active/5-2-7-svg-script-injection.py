"""

Script testing 5.2.7 control from OWASP ASVS 4.0:
'Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, 
especially as they relate to XSS resulting from inline scripts, and foreignObject.'

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



  attack = '<svg xmlns="http://www.w3.org/1999/svg"> <script> alert(1) </script> </svg>'

  msg = msg.cloneRequest();
  
  # setParam (message, parameterName, newValue)
  sas.setParam(msg, param, attack);

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);


  # Test the responses and raise alerts as below
  if (attack in str(msg.getResponseBody())):
    alertAttack = attack
    alertEvidence = attack + " in Response Body"
    sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
    url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

