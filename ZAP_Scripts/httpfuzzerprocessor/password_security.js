/*

Script testing the following password security controls from OWASP ASVS 4.0:

2.1.1 - Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined).

2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.

2.1.7 - Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords 
        either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. 
        If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. 
        If the password is breached, the application must require the user to set a new non-breached password.

2.1.9 - Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters.


Once the fuzzer is run with the provided wordlist, this script will check the response from each fuzzed request. 

	If the reponse status code is successful (200-209), the script will check the payload and add a custom status code if following criteria apply:
		1. Payload is less than 12 characters (2.1.1)
		2. Payload is greater than 128 characters (2.1.2)
		3. Payload is from top 1,000 most common passwords, taken from rockyou.txt (2.1.7)
		*This condition is true by default if the payload is greater than 12 and less than 128 characters long. This is because the wordlist contains only payloads from rockyou.txt and payloads that are too short or too long.
		*If changes are made to the wordlist or another one is used, false positive may be triggered so please review your results.
	
	If the response status code is NOT successful,  the script will check the payload and add a custom status code if following criteria apply (Note: these conditions are more prone to false positives):
		1. Payload is between 64 and 128 characters (2.1.2)
		2. Payload is valid length and contains special character (2.1.9)

*/


// Auxiliary variables/constants needed for processing.
var count = 1;
function containsSpecial(str){
	var regex = /[ !@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g;
	return regex.test(str);
}

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

     var payload = utils.getPayloads().toString();
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
     var length = payload.length;
     
     
	if (index != -1){//if, status code is found in list of successful codes (permitted)
          if (length < 12){
               
               fuzzResult.addCustomState("Key Custom State", "2.1.1 - Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined).")
          }else if (length > 128){
               
               fuzzResult.addCustomState("Key Custom State", "2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.")
          }else{
               fuzzResult.addCustomState("Key Custom State", "2.1.7 - Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords" 
        + "either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. "
        + "If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. "
        + "If the password is breached, the application must require the user to set a new non-breached password.")
}    

     }else{//if denied/error
          print(length);
          if (length > 63 && length < 129){
			fuzzResult.addCustomState("Key Custom State", "2.1.2 - Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied.")
		}else if ((length > 11 && length < 129) && containsSpecial(payload)){
               fuzzResult.addCustomState("Key Custom State", "2.1.9 - Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters.")
          }

     }
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

