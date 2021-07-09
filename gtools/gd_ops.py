'''
	Generic Google Drive File Operations
'''
import os,hashlib,time
from apiclient import errors
from apiclient.http import MediaFileUpload
DOWNLOAD_CHUNK_SZ = (1024*1024*256)
PROG_ROOT = os.getcwd()

def toMB(insz):
	return (float(insz) / (1024*1024))
 
#2**25 ~ 32MB
#2**20 ~ 1MB
def md5_for_file(f, block_size=2**25):
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()
	
def get_md5sum(infile):
	ff = open(infile,"rb")
	result = md5_for_file(ff)
	ff.close()
	return result 
	
def del_file(service,file_id):
	try:
		service.files().delete(fileId=file_id).execute()
	except errors.HttpError, error:
		print 'An error occurred: %s' % error
		exit(1)

def download_file(service,file,f0=0):
	f_offset = f0
	#If this is the first run, we do the hash check etc.
	if(f_offset == 0):
		#Check if local file with md5 exists - skip if so.
		if(os.path.exists(file['title'])):
			challenge_md5 = get_md5sum(file['title'])
			if(file['md5Checksum'] == challenge_md5):
				return #No need to download a file we already have.
			else:
				#We get rid of the imposter file.
				os.remove(file['title'])

	chk_sz = DOWNLOAD_CHUNK_SZ
	f = open(file['title'],"wb")
	file['fileSize'] = int(file['fileSize'])
	while(f_offset < file['fileSize']):
		if(f_offset > (file['fileSize'] - DOWNLOAD_CHUNK_SZ)):
			chk_sz = file['fileSize'] - DOWNLOAD_CHUNK_SZ
		else:
			chk_sz = DOWNLOAD_CHUNK_SZ
		if(file['fileSize'] < DOWNLOAD_CHUNK_SZ):
			
			resp, content = service._http.request(file['downloadUrl']) 
			if resp.status != 200 and resp.status != 206:
				print("Download Error - Retrying...")
				print(resp.status)
				f.close() 
				download_file(service,file,f_offset)
			else:
				f.write(content)
				f.close()
				return
		else:
			resp, content = service._http.request(file['downloadUrl'], headers={'Range': 'bytes=%d-%d' % (f_offset,f_offset+chk_sz)}) 
			if resp.status != 200 and resp.status != 206:
				print("Download Error - Retrying...")
				print(resp.status)
				f.close() 
				download_file(service,file,f_offset)
		f.write(content)
		#FUCKING OFF BY ONE!
		f_offset += chk_sz+1
		
		if(f_offset > file['fileSize']):
			f_offset = file['fileSize']
		print("Progress: %.2f%%(%d/%d)\r" % ((float(f_offset)/float(file['fileSize'])*100,f_offset/(1024*1024),file['fileSize']/(1024*1024))))			
	f.close() 	
	
		
#Recursively download files/folders from GDrive to a local path.
def download_dir(dsvc,dir_file,depth=0):
	
	cwd = os.getcwd()
	
	out_root = os.path.join(cwd,dir_file['title'])
	disp_path = out_root.replace(PROG_ROOT,"")
	print("ChangeDir to %s" % disp_path)
	if(not os.path.exists(out_root)):
		os.makedirs(out_root)
	os.chdir(out_root)
	
	file_list = get_file_meta(dsvc,"'%s' in parents" % dir_file['id'])
	
	counter = 1
	total = len(file_list)
	for file in file_list:
		if(file['mimeType'] == "application/vnd.google-apps.folder"):
			print("[%s%d/%d] %s (Directory)" % ((depth * "-"),counter,total,file['title']))
			download_dir(dsvc,file,depth+1)
		else:
			#We have a file.
			fsmb = float(float(file['fileSize']) / (1024*1024))
			print("[%s%d/%d] %s (%.2fMB)" % ((depth * "-"),counter,total,file['title'],fsmb))
			download_file(dsvc,file)
		counter +=1
	
	os.chdir("..")
	cwd = os.getcwd()
	disp_path = cwd.replace(PROG_ROOT,"")
	if(disp_path != ""):
		print("ChangeDir to %s" % disp_path)
	
#Recursively upload files/directories from a local path. Upload starts
#at the GDrive root path if you don't specify a parent id.
def upload_dir(dsvc,root_path,parent_id=None,depth=0):
	
	if(parent_id == None):
		#Get the ID of your Google Drive Root.
		parent_id = get_root_id(dsvc)
	
	dir_name = os.path.basename(os.path.normpath(root_path))	
	
	print("cd to %s" % root_path)
	#Check for parent dir and make if necessary.
	
	result = get_file_meta(dsvc,"'%s' in parents and title=\"%s\"" % (parent_id,dir_name))
	if(result == []):
		fr = create_dir(dsvc,dir_name,parent_id)
		cur_parent_id = fr['id']
	else:
		cur_parent_id = result[0]['id']


	#Upload everything - files first.
	for root, dir, files in os.walk(root_path):
		counter = 1
		for file in files:
			#Check if file exists - if md5sum matches, don't upload.
			fl = get_file_meta(dsvc,"'%s' in parents and title=\"%s\"" % (cur_parent_id,file))
			if(fl != []):
				drive_md5s = fl[0]['md5Checksum']
				local_md5s = get_md5sum(os.path.join(root_path,file))
				if(drive_md5s == local_md5s):
					print("[%s%d/%d] SKIPPED %s " % ((depth * "-"),counter,len(files),file))
					counter +=1
					#Delete Local File for now.
					os.remove(os.path.join(root_path,file))
					continue #We skip this file entirely because it already exists.
				else:
					#We delete the file on GDrive.			
					del_file(dsvc,fl[0]['id'])
					
			print("[%s%d/%d] %s  (%d bytes)" % ((depth * "-"),counter,len(files),file,os.path.getsize(os.path.join(root_path,file))))
			start_time = time.time()
			upload_file(dsvc, file, "", cur_parent_id, "", os.path.join(root_path,file))
			elapsed_time = time.time() - start_time
			dr_rate = toMB(os.path.getsize(os.path.join(root_path,file))) / elapsed_time
			print("Uploaded! %.2fMB/sec(%dseconds)." % (dr_rate,int(elapsed_time)))
			counter +=1
					
		#Upload each directory by recursion.
		for d in dir:
			upload_dir(dsvc,os.path.join(root_path,d),cur_parent_id,depth+1)
		break
		
def upload_file(service, title, description, parent_id, mime_type, filename):
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
		#We return the file object.
		return file
	except errors.HttpError, error:
		print 'An error occured: %s' % error
		#Try again.
		print("Retrying...")
		upload_file(service, title, description, parent_id, mime_type, filename)
		exit(1)
		

		

def create_dir(dsvc,dir_name,parent_id=None):
	body = {
	'title':dir_name,
	'descrtiption':'',
	'mimeType': 'application/vnd.google-apps.folder'
	}
	if(parent_id):
		body['parents'] = [{'id':parent_id}]
		
	try:
		file = dsvc.files().insert(body=body).execute()
		return file
	except errors.HttpError, error:
		print 'An error occured: %s' % error
		exit(1)
		
		
def get_file_by_id(dsvc,file_id):
	try:
		file = dsvc.files().get(fileId=file_id).execute()
		return file
	except errors.HttpError, error:
		if("HttpError 404" in str(error)):
			print("Error - File/Directory Not Found with that ID on this GDrive")
			exit(1)
		print 'An error occurred: %s' % error
		exit(1)
		
def get_file_meta(dsvc,q=None):
	result = []
	page_token = None
	while True:
		try:
			param = {}
			if(q != None):
				param['q'] = q
			if page_token:
				param['pageToken'] = page_token
			files = dsvc.files().list(**param).execute()
			result.extend(files['items'])
			page_token = files.get('nextPageToken')
			if not page_token:
				break
		except errors.HttpError, error:
			print 'An error occurred: %s' % error
			#Try Again.
			get_file_meta(dsvc,q)
			exit(1) #Used to be break :(
	return result
	

def get_root_id(drive_service):
	about = drive_service.about().get().execute()
	return about['rootFolderId']