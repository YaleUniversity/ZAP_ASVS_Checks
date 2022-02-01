"""

Script testing 5.3.6 control from OWASP ASVS 4.0:
'Verify that the application protects against JSON injection attacks, 
JSON eval attacks, and JavaScript expression evaluation.'

The scan function will check if a message returns JSON data by checking for "application/json" in the Content-Type response header.
If it does, it will try injecting various common JSON elements like [, ], {, }, etc... that might be used in a JSON injection attack.
The payload will include a key word along with the element. This way, when we check the response body for the payload, we can reudence 
the number of false positives from properly formatted JSON data.

The script will raise an alert if the payload is echoed in the response body (no sanitization or encoding)

"""

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
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
    for element in common_json_elements:
      attack = "json attack" + elment
      # setParam (message, parameterName, newValue)
      sas.setParam(msg, param, attack);

      # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
      sas.sendAndReceive(msg, False, False);


      # Test the responses and raise alerts as below
      if (attack in msg.getRequestBody()):
        alertEvidence = element + " not sanatized"
        sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

