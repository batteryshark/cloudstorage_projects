'''
	Google Drive Normalizer by rFx
	Background: Google Drive's design has always been centered around
	document managment, built-in revisions, and the idea of defying 
	normal filesystem conventions.

	For people storing documents, managing revisions, etc. - that's fine. 
	For those of us who want to use it like an actual filesystem, however... 
	it's not practical. Failed upload attempts can leave us with a ton of 
	duplicate files that needlessly waste space, and the hell from multiple 
	directories is such a pain.

	This script will take a root directory and aggregate directories with the 
	same name, then parse the directories and prompt to 
	orphan (delete all but the desired copy) or rename any duplicate files - 
	saving space and reflecting more of a traditional filesystem. 

'''

import os,sys,pickle,webbrowser,httplib2,hashlib,binascii
import oauth2client.client
import apiclient.discovery
import apiclient.http
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
			page_token = children.get('nextPageToken')
			if not page_token:
				break
		except errors.HttpError, error:
			print 'An error occurred: %s' % error
			break
	return ftbl	
def insert_file_into_folder(service, folder_id, file_id):
	new_parent = {'id': folder_id}
	try:
		return service.parents().insert(fileId=file_id, body=new_parent).execute()
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return None	
def remove_file_from_folder(service, folder_id, file_id):
	try:
		service.children().delete(folderId=folder_id, childId=file_id).execute()
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
def rename_file(service, file_id, new_title):
	try:
		file = {'title': new_title}
		updated_file = service.files().patch(fileId=file_id,body=file,fields='title').execute()
		return updated_file
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		return None
def move_file(service, file_id, old_parent_id,new_parent_id):
	insert_file_into_folder(service, new_parent_id, file_id)
	remove_file_from_folder(service, old_parent_id, file_id)

def duplicate_prompt(fid1,fid2,ftbl):
	while(1):
		print("1: %s %s %s" % (ftbl[fid1]['title'],ftbl[fid1]['modified'],ftbl[fid1]['sz']))
		print("2: %s %s %s" % (ftbl[fid2]['title'],ftbl[fid2]['modified'],ftbl[fid2]['sz']))
		print("[d]elete [r]ename?")
		resp = raw_input("> ")
		if(resp != "d" and resp != "r"):
			print("Invalid Input - Only r and d are supported.")
			continue
		while(1):
			print("Which File [1 or 2]?")
			res2 = raw_input("> ")
			if(res2 != "1" and res2 != "2"):
				print("Invalid Input - Only 1 and 2 are supported.")
				continue
			else:
				resp += res2
				break
		if(resp != "d1" and resp != "r1" and resp !="d2" and resp!="r2"):
			print("Invalid Input - Only r1 r2 d1 d2 are supported.")
			continue
		else:
			if(resp == "d1"):
				return "delete",fid1,None
			if(resp == "d2"):
				return "delete",fid2,None
			if(resp == "r1"):
				while(1):
					new_name = raw_input("Type New Name: ")
					for fk in ftbl.keys():
						if(ftbl[fk]['title'] == new_name):
							print("Error - Name already Exists!")
							continue
					return "rename",fid1,new_name
			if(resp == "r2"):
				while(1):
					new_name = raw_input("Type New Name: ")
					for fk in ftbl.keys():
						if(ftbl[fk]['title'] == new_name):
							print("Error - Name already Exists!")
							continue
					return "rename",fid2,new_name

def proc_dir(parent_id):
	print("Processing %s" % parent_id)
	#First, we get the list of all IDs in the directory.
	file_list = get_file_list(parent_id)
	#Then, we get the metadata for each (type, size, name, etc.)
	ftbl = get_meta(DRIVE_SERVICE,parent_id,file_list)
	#Then, we operate on all files, first (easier to deal with).
	for f in ftbl.keys():
		if(not f in ftbl.keys()):
			print("DEBUG: Skip Deleted Key")
			continue
		if(ftbl[f]['type'] == "directory"):
			continue
		else:
			curr_fname = ftbl[f]['title']
			curr_id = f
			curr_sum = ftbl[f]['md5']
			for g in ftbl.keys():
				if(g == f):
					continue
				if(curr_fname == ftbl[g]['title']):
					#If same filename and same hash, remove duplicate.
					if(ftbl[g]['md5'] == curr_sum):
						print("Pruning Duplicate:%s" % ftbl[g]['title'])
						remove_file_from_folder(DRIVE_SERVICE,parent_id,g)
						ftbl.pop(g)
					else:
						result_code, result_id, result_meta = duplicate_prompt(f,g,ftbl)
						if(result_code == "delete"):
							remove_file_from_folder(DRIVE_SERVICE,parent_id,result_id)
							ftbl.pop(result_id)
						if(result_code == "rename"):
							rs = rename_file(DRIVE_SERVICE,result_id,result_meta)
							ftbl[result_id]["title"] = result_meta
	#Then, we operate and merge on directories
	for f in ftbl.keys():
		if(not f in ftbl.keys()):
			print("DEBUG: Skip Deleted Key")
			continue
		if(ftbl[f]['type'] == "directory"):
			
			curr_fname = ftbl[f]['title']
			for g in ftbl.keys():
				if(g == f):
					continue
				if(curr_fname == ftbl[g]['title']):
					dup_folder_ids = get_file_ids(DRIVE_SERVICE,g)
					for d in dup_folder_ids:
						move_file(DRIVE_SERVICE, d,g,f)
					remove_file_from_folder(DRIVE_SERVICE, parent_id, g)
					ftbl.pop(g)
	#Finally, we recurse.
	for f in ftbl.keys():
		if(not f in ftbl.keys()):
			print("DEBUG: Skip Deleted Key")
			continue
		if(ftbl[f]['type'] == "directory"):
			proc_dir(f)		

def usage():
	print("%s root_dir_id" % sys.argv[0])
	exit(1)
if(__name__=="__main__"):
	if(len(sys.argv) < 2):
		usage()

	root_id = sys.argv[1]
	drive_login()

	proc_dir(root_id)
	print("Done!")
	
	
	
	