"""

Script testing 5.3.6 control from OWASP ASVS 4.0:
'Verify that the application protects against JSON injection attacks, 
JSON eval attacks, and JavaScript expression evaluation.'

The script will raise an alert if 

"""

def scanNode(sas, msg):

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "5.3.6 Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation."
  alertDescription = "Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = ""
  alertSolution = ""
  alertEvidence = "" 
  cweID = 830
  wascID = 0

  common_json_elements = ["[", "]", "{", "}", ",", ":", '"']

  # Debugging can be done using print like this
  #print('scan called for url=' + msg.getRequestHeader().getURI().toString())
  # Copy requests before reusing them
  msg = msg.cloneRequest();
  sas.sendAndReceive(msg, False, False);

  response_header = msg.getResponseHeader().getHeader("Content-Type")
  print(response_header)
  if ((response_header != None) and "application/json" in response_header):
    print("body ")

    # setParam (message, parameterName, newValue)
    #sas.setParam(msg, param, 'Your attack');

    # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    #sas.sendAndReceive(msg, False, False);


    # Test the responses and raise alerts as below
    if (True):
      sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

def scan(sas, msg, param, value):
  pass

