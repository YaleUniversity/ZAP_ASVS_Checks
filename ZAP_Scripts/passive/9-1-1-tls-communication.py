"""

Script testing 9.1.1 control from OWASP ASVS 4.0:
'Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications.'

The script will raise an alert if the client is able to connect the application through http which has no encryption.
 
"""
def scan(ps, msg, src):

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "9.1.1 Verify that TLS is used for all client connectivity."
  alertDescription = "Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
  alertSolution = "A request was made with HTTP: " + url + "\n" + "Ensure at least version TLSv1.2 is used for client connectivity."
  alertEvidence = "" 
  cweID = 319
  wascID = 0

  
  #if 'Cache-Control' and 'Pragma' headers are not present
  if ("http://" in url):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
