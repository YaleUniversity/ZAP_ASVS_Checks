"""

Script testing 5.3.2 control from OWASP ASVS 4.0:
'Verify that output encoding preserves the user's chosen character set and locale, 
such that any Unicode character point is valid and safely handled.'

The script will raise an alert if the response header "Content-Type" does not retatin 
the charcter set specified in the request header "Accept"

"""
from org.parosproxy.paros.network import HttpRequestHeader

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

  #list of character sets used in request
  character_sets = ["ISO-8859-1", "ISO-8859-15", "Latin-1", "Windows-1252", "UTF-8", "UTF-16", "UTF-32"]

  #clone message before sending
  msg = msg.cloneRequest();

  #loop through each character set and include it in request header
  for set in character_sets:
   
    #using text/html as static MIME type
    value = "text/html; charset=" + set

    #set Accept header in request to chosen character set
    msg.getRequestHeader().setHeader("Accept", value)
  
    #send message
    sas.sendAndReceive(msg, False, False);

    #get 'Content-Type' header from response 
    response_header = str(msg.getResponseHeader().getHeader("Content-Type"))

  
    #if the 'Content-Type' header does not incude the specfied character set, raise alert
    if (response_header != None and (set not in response_header)):
      alertEvidence = "Character set used: " + set
      sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

def scan(sas, msg, param, value):
  pass