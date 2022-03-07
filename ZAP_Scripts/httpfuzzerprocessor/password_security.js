/*

Script testing the following password security controls from OWASP ASVS 4.0:

2.1.1 - Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined).

2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.

2.1.7 - Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords 
        either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. 
        If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. 
        If the password is breached, the application must require the user to set a new non-breached password.

2.1.9 - Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters.


This script will 

*/


var ScriptsActiveScanner = Java.type('org.zaproxy.zap.extension.ascan.ScriptsActiveScanner');

// Auxiliary variables/constants needed for processing.
var count = 1;

function processMessage(utils, message) {
	message.getRequestHeader().setHeader("X-Unique-Id", count);
	count++;
}

function processResult(utils, fuzzResult){
	// All the above 'utils' functions are available plus:
	// To raise an alert:
	//    utils.raiseAlert(risk, confidence, name, description)
	// To obtain the fuzzed message, received from the server:
	//    fuzzResult.getHttpMessage()
	// To get the values of the parameters configured in the Add Message Processor Dialog.
	//    utils.getParameters() 
	// A map is returned, having as keys the parameters names (as returned by the getRequiredParamsNames()
	// and getOptionalParamsNames() functions below)
	// To get the value of a specific configured script parameter
	//    utils.getParameters().get("exampleParam1")

     var payload = utils.getPayloads();
     var codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 209];

     var response_code = fuzzResult.getHttpMessage().getResponseHeader().getStatusCode();
	var index = codes.indexOf(response_code);

     var msg = fuzzResult.getHttpMessage();

     var alertRisk= 0;
     var alertConfidence = 1;
     var alertTitle = "Fuzzer: Password Security";
     var alertDescription = "Payload: " + payload + "\n" + "Status Code: " + response_code + "\n" + "2.1.7 - Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords "
       + "either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. "
       + "If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. ";
       + "If the password is breached, the application must require the user to set a new non-breached password."
       + "cweID:  " + "521"
       + "\n" + "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy";
  	var url = msg.getRequestHeader().getURI().toString();
  	var alertParam = "";
  	var alertAttack = "";
  	var alertInfo = "https://owasp.org/www-project-json-sanitizer/migrated_content";
  	var alertSolution = "";
 	var alertEvidence = "";
  	var cweID = 830;
  	var wascID = 0;
     
     
	if (index != -1){//if, status code is found in list of successful codes (permitted)
          if (payload.length < 12){
               //alertDescription = "2.1.1 - Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined)."
          }
          if (payload.length > 128){
               //alertDescription = "2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied."
          }

     }else{//if denied/error
          if (payload.length < 12){
               //alertDescription = "2.1.9 - Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters."
          }
          if (payload.length > 11 && payload.length < 129){
               //alertDescription = "2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied."

          }

}ScriptsActiveScanner.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
          url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

