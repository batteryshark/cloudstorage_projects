'''
	EmuCloud Auth Module - GoogleDrive
'''
import os,pickle,webbrowser,oauth2client.client,httplib2,apiclient.http,apiclient.discovery

DRIVE_SERVICE = None
DBG_SAVE_AUTH = True
PROG_ROOT = os.getcwd()
CRED_PATH = os.path.join(PROG_ROOT,"cred.bin")
CLIENT_SECRETS = 'client_secrets.json'
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
		flow = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS, OAUTH2_SCOPE)
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
		
