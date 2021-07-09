'''
	GameCloud Auth Module - GoogleDrive
'''
import os,pickle,webbrowser,oauth2client.client,httplib2,apiclient.http,apiclient.discovery,tempfile

DRIVE_SERVICE = None
#Keep this false! It will save your authentication to a file for re-use, but it can be used by anyone that
#has the file.
DBG_SAVE_AUTH = True
PROG_ROOT = os.getcwd()
CRED_PATH = os.path.join(PROG_ROOT,"cred.bin")
CLIENT_SECRETS = """
{"installed":{"auth_uri":"https://accounts.google.com/o/oauth2/auth","client_secret":"ckGVrYYQ_GE7O4rL80ozlEXR","token_uri":"https://accounts.google.com/o/oauth2/token","client_email":"","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","oob"],"client_x509_cert_url":"","client_id":"665081966568.apps.googleusercontent.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs"}}
"""


OAUTH2_SCOPE = 'https://www.googleapis.com/auth/drive'

#Opens a web browser to authenticate the GDrive account.
#Also, makes a testing pickle object to keep authenticated
#for testing purposes.
def get_service():
	drive_service = None
	if(os.path.exists(CRED_PATH) and DBG_SAVE_AUTH == True):
		credentials = pickle.load(open(CRED_PATH,"rb"))
		http = httplib2.Http()
		credentials.authorize(http)
		drive_service = apiclient.discovery.build('drive', 'v2', http=http)
		return drive_service
	else:
		( cs_handle, cs_name ) = tempfile.mkstemp()
		os.write(cs_handle,CLIENT_SECRETS)
		flow = oauth2client.client.flow_from_clientsecrets(cs_name, OAUTH2_SCOPE)
		os.close(cs_handle)
		flow.redirect_uri = oauth2client.client.OOB_CALLBACK_URN
		authorize_url = flow.step1_get_authorize_url()
		webbrowser.open(authorize_url)
		code = raw_input('Enter verification code: ').strip()
		credentials = flow.step2_exchange(code)
		if(DBG_SAVE_AUTH == True):
			pickle.dump(credentials,open(CRED_PATH,"wb"))
		http = httplib2.Http()
		credentials.authorize(http)
		drive_service = apiclient.discovery.build('drive', 'v2', http=http)
		return drive_service


#Wrapper to return drive_service object.
def drive_login():
	print("Logging in - one sec...")
	return get_service()
	


if(__name__=="__main__"):
		#Test Login
		drive_service = drive_login()
		