'''
	Google Drive Undelete by rFx
	Description: This tool parses all files
	in your Google Drive and finds files that
	have been deleted or are hidden and prompts
	to move them to a "Recovery" directory.

'''

import os,sys,pickle,webbrowser,httplib2,hashlib,binascii
import oauth2client.client
import apiclient.discovery
import apiclient.http
from apiclient.http import MediaFileUpload
from apiclient import errors

# OAuth 2.0 scope that will be authorized.
# Check https://developers.google.com/drive/scopes for all available scopes.
OAUTH2_SCOPE = 'https://www.googleapis.com/auth/drive'

# Location of the client secrets.
CLIENT_SECRETS = 'client_secrets.json'
PROG_ROOT = os.getcwd()
DRIVE_SERVICE = None
if(os.name == "posix"):
	GD_BINARY = os.path.join(PROG_ROOT,"drive-linux")
else:
	GD_BINARY = os.path.join(PROG_ROOT,"drive-windows.exe")
CRED_PATH = os.path.join(PROG_ROOT,"cred.bin")

def drive_login():
	global DRIVE_SERVICE
	if(DRIVE_SERVICE == None):
		print("Logging in - one sec...")
		DRIVE_SERVICE = get_service()
	else:
		pass	
def get_meta(service,folder_id,ftbl):
	for f in ftbl.keys():
		file = service.files().get(fileId=f).execute()
	
		if("md5Checksum" in file.keys()):
			ftbl[f] = {"title":file['title'],"md5":file['md5Checksum'],"sz":file['fileSize'],"url":file['downloadUrl'],"type":"file","modified":file['modifiedDate']}
		else:
			ftbl[f] = {"title":file['title'],"type":"directory","sz":None,"md5":None,"modified":file['modifiedDate']}
	return ftbl
def get_service():
	drive_service = None
	if(os.path.exists(CRED_PATH)):
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
		pickle.dump(credentials,open(CRED_PATH,"wb"))
		http = httplib2.Http()
		credentials.authorize(http)
		drive_service = apiclient.discovery.build('drive', 'v2', http=http)
		return drive_service
def patch_property(service, file_id, key, new_value, visibility):
	try:
		patched_property = {'value': new_value}
		return service.properties().patch(fileId=file_id,propertyKey=key,visibility=visibility,body=patched_property).execute()
  	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return None
def print_property(service, file_id, key, visibility):
	p = service.properties().get(fileId=file_id, propertyKey=key, visibility=visibility).execute()	
	print(p)
def unhidelete_file(service, file_id,rabels):
	try:
		file = {'labels': rabels}
		updated_file = service.files().patch(fileId=file_id,body=file,fields='labels').execute()
		return updated_file
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return None	
def retrieve_all_files(service):
	result = []
	
	page_token = None
	counter = 0 
	while True:
		try:
			param = {}
			if page_token:
				param['pageToken'] = page_token
				#Note - Although the api says 1000 is the max
				#number of results, it only ever seems to return 460.
				param['maxResults'] = 1000 
			files = service.files().list(**param).execute()
			for fd in files['items']:
				#Skip directories - no point in saving an orphaned dir.
				if(fd['mimeType'] == "application/vnd.google-apps.folder"):
					continue
				''' Don't need this one
				if(fd['labels']['hidden']==True and fd['labels']['trashed'] == False):
					try:
						print("Found Hidden File: %s" % get_filename(fd['id']))
					except:
						pass
					res = raw_input("Press 'r' to recover: ")
					if(res == "r"):
						fd['labels']['hidden'] = False
						fd['labels']['trashed'] = False
						unhidelete_file(DRIVE_SERVICE, fd['id'],fd['labels'])
						move_orphan(DRIVE_SERVICE, fd['id'],recovery_fid)
				'''
				if(fd['labels']['hidden']==True and fd['labels']['trashed'] == True):
					print("Found Hidden Deleted File: %s" % get_filename(fd['id']))

					res = raw_input("Press 'r' to recover: ")
					if(res == "r"):
						fd['labels']['hidden'] = False
						fd['labels']['trashed'] = False
						unhidelete_file(DRIVE_SERVICE, fd['id'],fd['labels'])
						move_orphan(DRIVE_SERVICE, fd['id'],recovery_fid)
					
				if(fd['labels']['hidden']==False and fd['labels']['trashed'] == True):
					print("Found Deleted File: %s" % get_filename(fd['id']))
					res = raw_input("Press 'r' to recover: ")
					if(res == "r"):
						fd['labels']['hidden'] = False
						fd['labels']['trashed'] = False
						unhidelete_file(DRIVE_SERVICE, fd['id'],fd['labels'])
						move_orphan(DRIVE_SERVICE, fd['id'],recovery_fid)
					
					
				
			counter += len(files['items'])
			sys.stdout.write("Searched %d files...\r " % counter)
			
			page_token = files.get('nextPageToken')
			if not page_token:
				break
		except errors.HttpError, error:
			print 'An error occurred: %s' % error
			break
	return result
def insert_file_into_folder(service, folder_id, file_id):
	new_parent = {'id': folder_id}
	try:
		return service.parents().insert(fileId=file_id, body=new_parent).execute()
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return None	
def get_parents(service, file_id):
	parents = None
	try:
		parents = service.parents().list(fileId=file_id).execute()
		for parent in parents['items']:
			return "SKIP"
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return "ERROR"
	#retn None if no parents.
	return None
def get_filename(fid):
	file = DRIVE_SERVICE.files().get(fileId=fid).execute()
	return file['title']

def move_orphan(service, file_id,new_parent_id):
	insert_file_into_folder(service, new_parent_id, file_id)

def get_file_list(parent_id):
	global DRIVE_SERVICE
	ftbl = get_file_ids(DRIVE_SERVICE, parent_id)
	return ftbl
def get_file_ids(service, folder_id):
	ftbl = {}
	page_token = None
	while True:
		try:
			param = {}
			if page_token:
				param['pageToken'] = page_token
			children = service.children().list(folderId=folder_id, **param).execute()
			
			for child in children.get('items', []):
				ftbl[child['id']] = None
			old_page_token = page_token
			page_token = children.get('nextPageToken')

			if not page_token:
				break
		except errors.HttpError, error:
			print 'An error occurred: %s' % error
			page_token = old_page_token
			continue
		

	return ftbl	
def proc_recovery_dir(service,folder_id,ftbl):
	for f in ftbl.keys():
		file = service.files().get(fileId=f).execute()
		if(file['title'] == "Recovery"):
			return f
		
	mime_type = "application/vnd.google-apps.folder"
	body ={
	'title':"Recovery",
	'description':"Orphan-Recovered Files",
	'mimeType':mime_type
	}
	body['parents'] = [{'id':folder_id}]
	try:
		file = service.files().insert(body=body).execute()
		return file['id']
	except errors.HttpError, error:
		print 'An error occured: %s' % error
		return None
def create_recovery_dir():
	recovery_fid = None
	about = DRIVE_SERVICE.about().get().execute()
	root_id = about['rootFolderId']
	root_list = get_file_list(root_id)
	return proc_recovery_dir(DRIVE_SERVICE,root_id,root_list)
	
if(__name__=="__main__"):
	drive_login()
	#Make Recovery Directory if not exist
	#Get the Root Folder ID.
	print("Finding / Creating Recovery Directory...")
	recovery_fid = create_recovery_dir()
	print("Searching for Orphans in GDrive...")
	file_list = retrieve_all_files(DRIVE_SERVICE)

	print(" ")
	print("Done!")

