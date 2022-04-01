"""

Script testing 14.4.2 control from OWASP ASVS 4.0:
'Verify that all API responses contain a Content-Disposition: attachment;
filename="api.json" header (or other appropriate filename for the content
type).'
 
The script will raise an alert if 'Content-Disposition' header is present but not follow the format - Content-Disposition: attachment; filename=
 
"""

def scan(ps, msg, src):

  #find "Content-Disposition" header
  header = str(msg.getResponseHeader().getHeader("Content-Disposition"))

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "14.4.2 Verify that all API responses contain a Content-Disposition."
  alertDescription = "Verify that all API responses contain a Content-Disposition: attachment; filename='api.json'header (or other appropriate filename for the content type)."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
  alertSolution = "Use the format 'Content-Disposition: attachment; filename=' for API responses"
  alertEvidence = "" 
  cweID = 116
  wascID = 0
  
  # if "attachment; filename=" is not in "Content-Disposition" header, raise alert
  if ("attachment; filename=" not in header.lower()):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
