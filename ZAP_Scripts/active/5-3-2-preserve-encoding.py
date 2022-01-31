"""

Script testing 5.3.2 control from OWASP ASVS 4.0:
'Verify that output encoding preserves the user's chosen character set and locale, 
such that any Unicode character point is valid and safely handled.'

The script will raise an alert if the response header "Content-Type" does not retatin 
the charcter set specified in the request header "Accept"

"""
from org.parosproxy.paros.network import HttpRequestHeader

def changeAcceptHeader(msg, new_mime):
  header_to_list = str(msg.getRequestHeader()).split()
  print(header_to_list)
  accept_index = header_to_list.index('Accept:')
  header_to_list[accept_index + 1] = new_mime
  new_header = HttpRequestHeader(data)
  return new_header


def scanNode(sas, msg):
  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "5.3.2 Verify that output encoding preserves the user's chosen character set and locale."
  alertDescription = "Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = ""
  alertSolution = ""
  alertEvidence = "" 
  cweID = 176
  wascID = 0

  character_sets = ["ISO-8859-1", "ISO-8859-15", "Latin-1", "Windows-1252", "UTF-8", "UTF-16", "UTF-32"]
  request_header = str(msg.getRequestHeader().getHeader("Accept"))

  if (request_header != None and ("text" in request_header)):
    print("old:" + request_header)
    for set in character_sets:
      value = "text/html;charset=" + set 
      new_header = changeAcceptHeader(msg, value)
      
      if new_header != None:
        
        msg = msg.cloneRequest();

        msg.setRequestHeader(new_header)
        new = str(msg.getRequestHeader().getHeader("Accept"))

        sas.sendAndReceive(msg, False, False);
 
        response_header = str(msg.getResponseHeader().getHeader("Content-Type"))

        if (response_header != None and (set not in response_header)):
          alertEvidence = "Character set used: " + set
          sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
          url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

def scan(sas, msg, param, value):
  pass