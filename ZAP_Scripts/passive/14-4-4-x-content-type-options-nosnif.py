"""

Script testing 14.4.4 control from OWASP ASVS 4.0:
'Verify that all responses contain a X-Content-Type-Options: nosniff header.'

The script will raise an alert if 'X-Content-Type-Options: nosniff header is not present. 

"""

def scan(ps, msg, src):
 
  #find "X-Content-Type-Options" header
  header = str(msg.getResponseHeader().getHeader("X-Content-Type-Options"))

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "14.4.4 Verify that all responses contain a X-Content-Type-Options: nosniff header."
  alertDescription = "The X-Content-Type-Options response HTTP header is used by the server to prevent browsers from guessing the media type ( MIME type). This is known as MIME sniffing in which the browser guesses the correct MIME type by looking at the contents of the resource. The absence of this header might cause browsers to transform non-executable content into executable content."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
  alertSolution = "Add 'X-Content-Type-Options: nosniff header to all HTTP responses."
  alertEvidence = "X-Content-Type-Options" + header
  cweID = 116
  wascID = 0

  #if "no sniff" is not in header, raise alert  
  if ("nosniff" not in header.lower()):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
