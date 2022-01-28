"""
The scanNode function will typically be called once for every page 
The scan function will typically be called for every parameter in every URL and Form for every page 

Note that new active scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""
from org.parosproxy.paros.network import HttpRequestHeader

def changeAcceptHeader(msg, new_mime):
  header_to_list = str(msg.getRequestHeader()).split()
  accept_index = header_to_list.index('Accept:')
  header_to_list[accept_index + 1] = new_mime

  data = ' '.join(header_to_list)
  new_header = HttpRequestHeader(data)
  return new_header


def scanNode(sas, msg):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString());
  '''
  method = msg.getRequestHeader().getMethod()
  url = msg.getRequestHeader().getURI()
  version = "1.1"
  params = "Accept: "
'''
  # Copy requests before reusing them
  msg = msg.cloneRequest();
  new_header = changeAcceptHeader(msg, 'text/html')
  
  msg.setRequestHeader(new_header)
  print(msg)
  print(msg.getRequestHeader)


  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the response here, and make other requests as required
  #reponse_header = msg.getResponseHeader().getHeader("Content-Type")
'''
  if ("test" in response_header):
    sas.raiseAlert(1, 1, 'Active Vulnerability title', 'Full description', 
    msg.getRequestHeader().getURI().toString(), 
      param, 'Your attack', 'Any other info', 'The solution ', '', 0, 0, msg);'''

def scan(sas, msg, param, value):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
    ' param=' + param + ' value=' + value);

  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # setParam (message, parameterName, newValue)
  sas.setParam(msg, param, 'Your attack');

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the response here, and make other requests as required
  if (True):
  	# Change to a test which detects the vulnerability
    # raiseAlert(risk, int confidence, String name, String description, String uri, 
    #		String param, String attack, String otherInfo, String solution, String evidence, 
    #		int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # confidence: 0: false positive, 1: low, 2: medium, 3: high
    sas.raiseAlert(1, 1, 'Active Vulnerability title', 'Full description', 
    msg.getRequestHeader().getURI().toString(), 
      param, 'Your attack', 'Any other info', 'The solution ', '', 0, 0, msg);