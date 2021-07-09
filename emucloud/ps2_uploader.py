'''
	Decompresses ReDUMP file, Uses file name as game name.
	Compresses file as gz (either ISO or .BIN).
	Then, uploads file to EmuCloud account directory with the default attrs.
	
	TODO Later - Make an editor that can alter metadata en-masse.
	
'''
import gc_auth,os,sys,hashlib,binascii
from apiclient import errors
from apiclient.http import MediaFileUpload
GAME_ATTR_BASE = {
"media_key":"EmuCloud",
"game_name":"",
"game_description":"",
"game_publisher":"",
"game_developer":"",
"game_region":"",
"game_system":"PS2",
"game_emu":"PCSX2",
"game_emu_status":"",
"game_year":"",
"game_players":"",
"game_preview_video":"",
"game_cover_front":"",
"game_cover_back":"",
"game_media":"",
"game_sha1":"",
"game_content_rating":""
}

#2**25 ~ 32MB
#2**20 ~ 1MB
def sha1_for_file(f, block_size=2**25):
    sha1 = hashlib.sha1()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha1.update(data)
    return sha1.hexdigest()
	
def get_sha1sum(infile):
	ff = open(infile,"rb")
	result = sha1_for_file(ff)
	ff.close()
	return result 

def get_file_list(drive_service, parent_id):
	ftbl = get_file_ids(drive_service, parent_id)
	return ftbl

def get_file_ids(service, folder_id):
	ftbl = {}
	page_token = None
	while True:
		try:
			param = {}
			if page_token:
				param['pageToken'] = page_token
				param['maxResults'] = 1000
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
	
def proc_emucloud_dir(service,folder_id,ftbl):
	for f in ftbl.keys():
		file = service.files().get(fileId=f).execute()
		if(file['title'] == "EmuCloud"):
			return f
		
	mime_type = "application/vnd.google-apps.folder"
	body ={
	'title':"EmuCloud",
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

def insert_property(service, file_id, key, value, visibility):
	body = {
		'key': key,
		'value': value,
		'visibility': visibility
	}

	try:
		p = service.properties().insert(
				fileId=file_id, body=body).execute()
		return p
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
	return None

def insert_file(service, title, description, parent_id, mime_type, filename):

	media_body = MediaFileUpload(filename, mimetype=mime_type, resumable=True)
	body = {
		'title': title,
		'description': description,
		'mimeType': mime_type
	}
	# Set the parent folder.
	if parent_id:
		body['parents'] = [{'id': parent_id}]

	try:
		file = service.files().insert(
				body=body,
				media_body=media_body).execute()

		# Uncomment the following line to print the File ID
		# print 'File ID: %s' % file['id']

		return file['id']
	except errors.HttpError, error:
		print 'An error occured: %s' % error
		return None

def retrieve_properties(service, file_id):

	try:
		props = service.properties().list(fileId=file_id).execute()
		return props.get('items', [])
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
	return None
	
def create_emucloud_dir(drive_service):
	about = drive_service.about().get().execute()
	root_id = about['rootFolderId']
	root_list = get_file_list(drive_service, root_id)
	return proc_emucloud_dir(drive_service,root_id,root_list)
	
if(__name__=="__main__"):
	if(os.path.exists("out")):
		os.system("rm out/* 2>> /dev/null")
	else:
		os.path.makedirs("out")
	result = os.popen("7za e -oout %s" % sys.argv[1]).read()
	base_gamename,ext = os.path.splitext(sys.argv[1])
	base_gamename = base_gamename.replace("\\","")
	if(not "Everything is Ok" in result):
		print("Extract Failed!")
		exit(1)
	#Remove any cue file and gzip.
	os.system("rm out/*.cue 2>>/dev/null")
	os.system("gzip out/*")
	
	#Make new entry.
	e = GAME_ATTR_BASE
	e["game_name"] = base_gamename
	gz_filename = ""
	for dirpath, dirnames, filenames in os.walk("out"):
		for f in filenames:
			if(f.endswith("gz")):
				gz_filename = os.path.join("out",f)
	
	e["game_sha1"] = get_sha1sum(gz_filename)
	print("Uploading %s" % e["game_name"])
	print("SHA1: %s" % e["game_sha1"])
	
	#Login to Google Drive
	dsvc = gc_auth.drive_login()
	gc_fid = create_emucloud_dir(dsvc)
	#TODO - Upload Preview Video if available.
	#TODO - Upload Front,Back,CD if available.
	print("Uploading Game Image, Please Wait...")
	game_fid = insert_file(dsvc, "%s.gz" % e["game_name"], "", gc_fid, "", gz_filename)
	print("Adding EmuCloud Metadata...")
	#Add Metadata
	for gk in e.keys():
		print(gk)
		insert_property(dsvc, game_fid, gk, e[gk], "PRIVATE")
	
		
	#Clean up
	os.system("rm out/*")
	print("Done!")
