"""

Script testing 14.3.3 control from OWASP ASVS 4.0:
'Verify that the HTTP headers or any part of the HTTP response do not expose
detailed version information of system components.'

The script will raise an alert if
	1. Server
	2. X-Powered-By
headers are present 

"""

def scan(ps, msg, src):
  
  #search response header for "Server" and "X-Powered-By" headers
  header_server = str(msg.getResponseHeader().getHeader("Server"))
  header_xpowered = str(msg.getResponseHeader().getHeader("X-Powered-By"))

  #alert parameters
  alertRisk= 2
  alertConfidence = 2
  alertTitle = "14.3.3 Verify that the HTTP headers do not expose detailed version information of system components."
  alertDescription = "14.3.3 Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = ""
  solutions = ["Ensure Server header in HTTP response does not expose server version information.", "Ensure X-Powered-By header in HTTP response does not expose server version information."]
  alertSolution = ""
  alertEvidence = "" 
  cweID = 200
  wascID = 0

  #if "Server" header is valid, add solution and evidence to alert
  if (header_server != "None"):
    alertSolution += solutions[0]
    alertEvidence += "Server: " + header_server
  #if "Server" header is valid, add solution and evidence to alert
  if (header_xpowered != "None"):
    alertSolution += solutions[1]
    alertEvidence += "X-Powered-By: " + header_xpowered
  
  #if the alert solution has been changed, raise alert
  if (alertSolution != ""):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
