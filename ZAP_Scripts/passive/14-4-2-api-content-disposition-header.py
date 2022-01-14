"""

Script testing 14.4.2 control from OWASP ASVS 4.0:
'Verify that all API responses contain a Content-Disposition: attachment;
filename="api.json" header (or other appropriate filename for the content
type).'

The script will raise an alert if 'Content-Disposition' header is present but not follow the format - Content-Disposition: attachment; filename=

"""

def scan(ps, msg, src):

  header = str(msg.getResponseHeader().getHeader("Content-Disposition"))

  alertRisk= 0
  alertConfidence = 1
  alertTitle = "3.4.1 Verify that cookie-based session tokens have the 'Secure' attribute set."
  alertDescription = "Verify that all API responses contain a Content-Disposition: attachment; filename='api.json'header (or other appropriate filename for the content type)."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
  alertSolution = "Use the format 'Content-Disposition: attachment; filename=' for API responses"
  alertEvidence = "" 
  cweID = 116
  wascID = 0
  
  if (header != "None" and "attachment; filename=" not in header.lower()):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
