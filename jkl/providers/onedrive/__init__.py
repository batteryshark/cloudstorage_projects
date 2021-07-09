# -*- encoding: utf-8 -*-
'''
    OneDrive Provider Driver for libjkl
    2015 Professor Batteryshark
'''
import os,sys,requests,hashlib,pickle,time,json,urllib,dill,binascii
from Crypto.Cipher import AES
import multiprocessing as mp

'''
[Functionality I can't do without an API update]
* delete file (perm) - not implemented yet
* untrash file - not implemented yet

[Functionality to implement]
X locally hash files
X login
X check authentication and refresh auth if necessary
X cache credentials
X get info about the cloud store itself
X download a file to memory
X trash file
X move file
X rename file
X copy file
X get path to access file (url if necessary)
X get info about a specific file
X create directory
X Upload a file.
X Upload a large file.
X Download a file.
X Download entire directory (recursively)
X Upload entire directory (recursively)
X list children in a directory of a parent_id
X search for a file by optional keyword and/or parent_id
X Upload a massive file (>10GB)
X Ls massive files properly
X move massive file
X copy massive file
X rename massive file
X trash massive file
X Download a massive file (>10GB)


'''


#Constants
DOWNLOAD_CHUNK_SIZE = 1024*1024*50 #50MB
MASSIVE_CHUNK_SIZE = 1024*1024*10240 #10GB
MB = 1024*1024

AUTH_URI = "https://login.live.com/oauth20_authorize.srf"
TOKEN_URI = "https://login.live.com/oauth20_token.srf"
REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"#"http://www.hali0x.net/redirect"
SCOPES = "wl.signin,wl.contacts_skydrive,wl.offline_access,onedrive.readwrite,wl.skydrive_update"



'''
==========================
 Utility Functions
==========================
'''
#Hash a local file with block size default being 2^25 or 32MB.
def sha1_for_file(f, byte_range=None, block_size=2**25):
	sha1 = hashlib.sha1()

	if(byte_range!=None):
		f.seek(byte_range[0],0)
	while True:
		if(byte_range != None):
			if(f.tell()+block_size > byte_range[1]):
				data = f.read(byte_range[1] - f.tell())
				sha1.update(data)
				break
			else:
				data = f.read(block_size)
		else:
			data = f.read(block_size)
		if not data:
			break
		sha1.update(data)
	return sha1.hexdigest()

def get_sha1sum(infile,byte_range=None):
	ff = open(infile,"rb")
	result = sha1_for_file(ff,byte_range=byte_range)
	ff.close()
	return result 

def get_adler32(infile):
	asum = 1
	with open(infile) as f:
		while True:
			data = f.read(256*1024*1024)
			if not data:
				break
			asum = adler32(data,asum)
			if asum < 0:
				asum += 2**32
	return asum

#Change file sizes into a more easily readable format.
def sizeof_fmt(num, suffix='B'):

		for unit in [' ',' K',' M',' G',' T',' P',' E',' Z']:
			if abs(num) < 1024.0:
				return "%3.1f%s%s" % (num, unit, suffix)
			num /= 1024.0
		return "%.1f%s%s" % (num, ' Y', suffix)

#Create Sparsefile for large placeholders.
def create_sparsefile(path,size):
	f = open(path,"wb")
	f.seek(size-1)
	f.write("\0")
	f.close()

'''
==========================
 jkl Crypto Functions
==========================
'''
def encrypt_block(self,data):
	in_key = self.client_config.get('encryption','aes_key')
	in_key = binascii.unhexlify(in_key)
	in_iv =  self.client_config.get('encryption','aes_iv')

	aescrypt = AES.new(in_key, AES.MODE_CFB, in_iv)
	return aescrypt.encrypt(data)

def decrypt_block(self,data):
	#Turn it back into a bytearray.
	in_key = self.client_config.get('encryption','aes_key')
	in_key = binascii.unhexlify(in_key)
	in_iv =  self.client_config.get('encryption','aes_iv')
	aescrypt = AES.new(in_key, AES.MODE_CFB, in_iv)		
	return aescrypt.decrypt(data)


def decrypt_str(self,in_str):
	#Get Real Filename.
	if(in_str.endswith(".jcf")):
		in_str = in_str[:-4]
	in_str = binascii.unhexlify(in_str)
	in_key = self.client_config.get('encryption','aes_key')
	in_key = binascii.unhexlify(in_key)
	in_iv =  self.client_config.get('encryption','aes_iv')
	aescrypt = AES.new(in_key, AES.MODE_CFB, in_iv)
	return aescrypt.decrypt(in_str)

def encrypt_str(self,in_str):
	in_key = self.client_config.get('encryption','aes_key')
	in_key = binascii.unhexlify(in_key)
	in_iv = self.client_config.get('encryption','aes_iv')
	aescrypt = AES.new(in_key, AES.MODE_CFB, in_iv)
	return binascii.hexlify(aescrypt.encrypt(in_str))

def generate_jcf_name(enc_name):
	return enc_name+".jcf"

def jcf_generate_description_hash(self,original_hash):
	in_key = self.client_config.get('encryption','aes_key')
	in_iv = self.client_config.get('encryption','aes_iv')
	return "jcf_hash:"+encrypt_str(self,'nonproliferation'+original_hash)

#Returns the original file hash or an error.
def jcf_decrypt_description_hash(self,description):
	description = decrypt_str(self,description.replace("jcf_hash:",""))
	if("nonproliferation" in description):
		description = description.replace("nonproliferation","")	
		return description
	else:
		return "ERR"


def set_current_aes_key(self,password,in_iv=None):
	s256 = hashlib.sha256()
	s256.update(password)
	in_key = s256.hexdigest()
	if(in_iv == None):
		in_iv = in_key[:8]+in_key[:8]
	
	self.client_config.set('encryption','aes_key',in_key)
	self.client_config.set('encryption','aes_iv',in_iv)

def clear_current_aes_key(self):
	self.client_config.set('encryption','aes_key',"")
	self.client_config.set('encryption','aes_iv',"")	



'''
==========================
 jkl Library Function
==========================
'''
#Run when the library is first loaded with a new provider license.
def init(self):
	try:
		access_check(self)
	except:
		log_in(self)

'''
==========================
 Authentication Functions
==========================
'''
# Refresh access token if expiring in the next minute.
def access_check(self):
    if self.client_config.getint('session','token_expiration') - 60 < time.time():
        refresh_access_token(self)


# Dump credentials to disk to cache login authorization.
def save_creds(self,access_token,refresh_token,token_expiration):
    cfgfile = open(self.client_info_file,'w')
    self.client_config.set('session','access_token',access_token)
    self.client_config.set('session','refresh_token',refresh_token)
    self.client_config.set('session','token_expiration',str(int(token_expiration)))
    self.client_config.write(cfgfile)
    cfgfile.close()

# Get new refresh token.
def refresh_access_token(self):
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    payload = {
        'redirect_uri': REDIRECT_URI,
        'client_id': self.client_config.get('client','client_id'),
        'grant_type': 'refresh_token',
        'refresh_token': self.client_config.get('session','refresh_token'),
        'client_secret': self.client_config.get('client','client_secret'),
    }
    # Keep trying until we log in.
    while 1:
        r = requests.post(TOKEN_URI, data=payload, headers=headers)
        if (r.status_code != 200):
            print("Refresh Token Error")
            print(r.status_code)
            print(r.content)
            time.sleep(5)
        else:
            break

    data = json.loads(r.content)
    refresh_token = data['refresh_token']
    access_token = data['access_token']
    token_expiration = time.time() + data['expires_in']
    save_creds(self,access_token,refresh_token,token_expiration)  # File Navigation Mechanisms


# Log In
def log_in(self):


    # Step 1 - Get Authorization
    params = {
        "client_id"    : self.client_config.get('client','client_id'),
        "scope"        : SCOPES,
        "response_type": 'code',
        "redirect_uri" : REDIRECT_URI
    }


    while 1:
        r = requests.get(AUTH_URI, params=params)
        if (r.status_code != 200):
            print("REGISTRATION ERROR")
            print(r.status_code)
            print(r.content)
            time.sleep(5)
        else:
            break

    # If UI - this will open a window.
    try:
        webbrowser.open(r.url)
    except:
        pass
    # USER INTERACTION.
    print("No GUI - Go to This Link:")
    print(r.url)
    print(" ")

    response_code = raw_input("Paste Response Code:")

    # Step 2 - Get the Tokens.
    headers = {
        'content-type':'application/x-www-form-urlencoded'
    }

    payload = {
        "redirect_uri":REDIRECT_URI,
        "client_id":self.client_config.get('client','client_id'),
        'grant_type':'authorization_code',
        'client_secret':self.client_config.get('client','client_secret'),
        'code':response_code
    }

    while 1:
        r = requests.post(TOKEN_URI, data=payload, headers=headers)
        if (r.status_code != 200):
            print("Auth Response Error")
            print(r.status_code)
            print(r.content)
            time.sleep(5)
        else:
            break

    data = json.loads(r.content)

    # Copy Response Data To Driver.
    refresh_token = data['refresh_token']
    access_token = data['access_token']
    token_expiration = time.time() + data['expires_in']
    save_creds(self,access_token,refresh_token,token_expiration)
 

'''
==========================
 Info Functions
==========================
'''
# Get info about storage endpoint.
def get_about(self):
    data = ""
    url = 'https://api.onedrive.com/v1.0/drive'
    while 1:
        access_check(self)
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
        r = requests.get(url,headers=headers)

        if r.status_code != 200:
            time.sleep(5)
        else:
            break

    # TODO - Standardize the data at some point...
    return r.json()

'''
==========================
 Download Functions
==========================
'''
#Pull a file into a memory buffer - optional range tuple.
def stream_download(self,file_id,q=None,out_path=None,byte_range=None):
	
	if(out_path != None):
		self = dill.loads(self)
	url = 'https://api.onedrive.com/v1.0/drive/items/%s/content' % file_id
	#Check for Errors and repeat if issue.
	response = 0
	while response != 200 and response != 206:
		try:
			access_check(self)
			headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
			if(byte_range != None):
				headers['Range'] = 'bytes=%d-%d' % (byte_range[0],byte_range[1])
				try:
					r = requests.get(url,headers=headers)
				except:
					continue
				if(r == None):
					continue
				data = r.content
				response = r.status_code
		except:
			continue
		
				
		
		if response != 200 and response != 206:
			print("stream_download err: %d" % response)
			continue
		#Decrypt Data if Encrypted
		if(self.client_config.get('encryption','aes_key') != ""):
			fmeta = stat_file(self,file_id)
			data = decrypt_block(self,data)

		#Short-Circuit for file saving.
		if(out_path != None):
			
			q.put((byte_range[0],data))			
			if(self.client_config.getboolean('rest','rest_callbacks') != False):
				gf = requests.get("%s/download_progress?chk_sz=%s" % (self.client_config.get('rest','rest_callback_url'),str(len(data))))
			return "DONE"
	return data

#Download files in directory.
def download_directory(self,out_path,parent_id):
	parent_dir_meta = stat_file(self,parent_id)
	#Sanity-Check to ensure the id passed is actually a directory.
	if("file" in parent_dir_meta.keys()):
		print("Given parent_id is a file - downloading...")
		download_file(self,out_path,parent_id)
		return
	out_path = os.path.join(out_path,parent_dir_meta['name'])
	print("Downloading to %s..." % out_path)
	if(not os.path.exists(out_path)):
		os.makedirs(out_path)
	dir_listing = ls(self,parent_id)

	#Files First
	file_bucket = []
	massive_file_bucket = []
	for item in dir_listing:
		if("file" in item.keys()):
			if(os.path.exists(os.path.join(out_path,item['name']))):
				lhash = get_sha1sum(os.path.join(out_path,item['name'])).upper()
				if(item['file']['hashes']['sha1Hash'] == lhash):
					continue	
			#Move massive to their own thing...
			if("_massive" in item['id']):
				massive_file_bucket.append({'path':out_path,'id':item['id']})
			else:
				file_bucket.append({'path':out_path,'id':item['id']})
	if(len(file_bucket) > 0):
		#Check for multiproc downloading...
		if(self.client_config.getboolean('download', 'multiproc_download') == False):
			for fl in file_bucket:
				#Single-Process
				download_file(self,fl['path'],fl['id'])
		else:
			manager = mp.Manager()

			slf = dill.dumps(self)
			  
			pool = mp.Pool(processes=self.client_config.getint('download', 'multiproc_download_maxprocs'))
			
			jobs = []
			
						
			for fl in file_bucket:
				job = pool.apply_async(download_file,(slf,fl['path'],fl['id']))
				jobs.append(job)

			# collect results from the workers through the pool result queue
			for job in jobs: 
				job.get()

			pool.close()	

	#Process Massive files with multicore support.
	if(len(massive_file_bucket) > 0):
		for ml in massive_file_bucket:
			download_file(self,ml['path'],ml['id'],in_daemon=False)

	#Then, we'll make directories and recurse.
	for item in dir_listing:

		if("folder" in item.keys()):
			print(item)
			download_directory(self,out_path,item['id'])


#Master download function; detours to other functions.
def download_file(self,out_path,file_id,in_daemon=True):
	global time
	try:
		self = dill.loads(self)
	except:
		pass

	if('_massive' in file_id):
		#Get info for root file.
		fmeta = stat_file(self,file_id.split("_massive")[0])
		parent_id = fmeta['parentReference']['id']
		base_name = fmeta['name'][:fmeta['name'].rfind("_")]
		chunk_list = find(self,parent_id=parent_id,q='%s*' % base_name,massive='YES')
		#fmeta['size']
		#Might want to use LS here eventually to ensure we dont get
		#results from deeper directories...
		master_entry = find(self,parent_id=parent_id,q='%s*' % base_name)
		fmeta = {'name':master_entry[0]['name'],'size':master_entry[0]['size']}

	else:
		fmeta = stat_file(self,file_id)

	print("Starting Download: %s  %s" % (fmeta['name'],sizeof_fmt(int(fmeta['size']))))

	start_time = time.time()
	out_path = os.path.join(out_path,fmeta['name'])
	if('_massive' in file_id):
		download_file_massive(self,out_path,chunk_list,fmeta,in_daemon=in_daemon)

	elif(int(fmeta['size']) > DOWNLOAD_CHUNK_SIZE):
		if(self.client_config.getboolean('download', 'multiproc_download_large') == False):
			download_file_large(self,out_path,file_id,massive=None)
		else:
			download_file_large_mc(self,out_path,file_id,self.client_config.getint('download', 'multiproc_download_large_maxprocs'),massive=None)
	else:
		download_file_small(self,out_path,file_id)
	elapsed_time = time.time() - start_time
	print("%s Finished @ %s/sec" % (out_path,sizeof_fmt(int(fmeta['size'])/elapsed_time)))

def download_file_massive(self,out_path,chunk_list,fmeta,in_daemon=True):
	chunk_list = sorted(chunk_list)
	while 1:
		file_down_progress = 0
		#Check if file exists and if hashes add up - if not, make the file.

		if(os.path.exists(out_path)):
			if(int(os.path.getsize(out_path)) == int(fmeta['size'])):
				print("Hash Checking File Chunks - Please Wait...")
				tmp_lst = []

				for i in range(0,len(chunk_list)):

					#Get chunk size from filename
					down_massive_chunk_size = int(chunk_list[i]['name'][chunk_list[i]['name'].rfind(".jmf_")+5:].split("_")[0]) * MB

					master_offset = (int(chunk_list[i]['name'].split("_")[-1]) - 1 ) * down_massive_chunk_size
					if(master_offset+down_massive_chunk_size < fmeta['size']):
						byte_range = (master_offset,master_offset+down_massive_chunk_size)
					else:
						byte_range = (master_offset,fmeta['size'])


					local_sha1 = get_sha1sum(out_path,byte_range=byte_range).upper()

					if(chunk_list[i]["file"]['hashes']['sha1Hash'] != local_sha1):

						tmp_lst.append(chunk_list[i])
					else:
						print("Hash matches for part %d - skipping..." % int(chunk_list[i]['name'].split("_")[-1]))
						file_down_progress+=int(chunk_list[i]['size'])
				chunk_list = tmp_lst
			else:
				os.remove(out_path)
				create_sparsefile(out_path,int(fmeta['size']))
				down_massive_chunk_size = int(chunk_list[0]['name'][chunk_list[0]['name'].rfind(".jmf_")+5:].split("_")[0]) * MB
		else:
			create_sparsefile(out_path,int(fmeta['size']))
			down_massive_chunk_size = int(chunk_list[0]['name'][chunk_list[0]['name'].rfind(".jmf_")+5:].split("_")[0]) * MB
		if(len(chunk_list) == 0):
			break
		print("Downloading %d parts..." % len(chunk_list))
		fmeta['massive_chunk_size'] = down_massive_chunk_size
	
		#Check for multiproc downloading...
		
		if(self.client_config.getboolean('download', 'multiproc_download_large') == True and in_daemon == False):
			manager = mp.Manager()
			q = manager.Queue()
			slf = dill.dumps(self)
			
			pool = mp.Pool(processes=self.client_config.getint('download', 'multiproc_download_large_maxprocs'))
			watcher = pool.apply_async(download_chunk_listener, (q,out_path,int(fmeta['size']),))
			jobs = []
			if(file_down_progress > 0):
				q.put(('skip',file_down_progress))
						
			for chunk in chunk_list:
				kwargs = {
				'massive':{'chunk_info':chunk,'fmeta':fmeta},
				'q':q,
				'in_daemon':in_daemon
				}
				job = pool.apply_async(download_file_large,(slf,out_path,chunk['id']),kwargs)
				jobs.append(job)

			# collect results from the workers through the pool result queue
			for job in jobs: 
				job.get()

			q.put('kill')
			pool.close()	


		else:		
			for chunk in chunk_list:
				#Single-Process

				download_file_large(self,out_path,chunk['id'],massive={'chunk_info':chunk,'fmeta':fmeta,'file_progress':file_down_progress})
				file_down_progress+=int(chunk['size'])
	


def download_chunk_listener(q,out_path,total_size):
	'''listens for messages on the q, writes to file. '''
	bytes_written = 0
	fname = os.path.split(out_path)[-1]
	f = open(out_path, 'rb+')
	f.seek(0,0)
	while 1:
		m = q.get()
		if(m == 'kill'):
			break
		if(m[0] == 'skip'):
			bytes_written+=m[1]
			continue
		f.seek(m[0])
		f.write(m[1])
		
		bytes_written += len(m[1])
		print("%s - %s/%s" % (fname,sizeof_fmt(bytes_written),sizeof_fmt(total_size)))
		f.flush()
	f.close()

#Utilizes multiple processes to speed up downloads
#WARNING: This has an insane impact on overall system performance.
def download_file_large_mc(self,out_path,file_id,max_pool=5,massive=None):
	file_meta = stat_file(self,file_id)
	total_size = int(file_meta['size'])
	file_parts = []
	
	access_check(self)
	create_sparsefile(out_path,total_size)

	for i in range(-1,total_size,DOWNLOAD_CHUNK_SIZE):
		if(i + DOWNLOAD_CHUNK_SIZE > total_size):
			
			remaining = total_size - i
			new_range = (i+1,i+remaining)
			file_parts.append(new_range)
			
		else:
			new_range = (i+1,i+DOWNLOAD_CHUNK_SIZE)
			file_parts.append(new_range)
	manager = mp.Manager()
	q = manager.Queue()   
	pool = mp.Pool(processes=max_pool)
	
	slf = dill.dumps(self)
	
	#Set up file write listener.
	watcher = pool.apply_async(download_chunk_listener, (q,out_path,total_size,))
	jobs = []

	for fl in file_parts:
		kwargs = {
		'out_path':out_path,
		'byte_range':fl,
		'q':q
		}
		#stream_download(slf,file_id,out_path=out_path,byte_range=fl)
		job = pool.apply_async(stream_download,(slf,file_id),kwargs)
		jobs.append(job)

	# collect results from the workers through the pool result queue
	for job in jobs: 
		job.get()

	#now we are done, kill the listener
	q.put('kill')
	pool.close()


	#Hash test to determine if we fucked up the splitting.

	lhash = get_sha1sum(out_path).upper()
	#print("%s ? %s" % (lhash,file_meta['file']['hashes']['sha1Hash']))
	if(file_meta['file']['hashes']['sha1Hash'] == lhash):
		print("Hash Matches!")
	else:
		print("Hash Mismatch!")
def download_file_large(self,out_path,file_id,massive=None,q=None,in_daemon=True):
	try:
		self = dill.loads(self)
	except:
		pass
		

	file_meta = stat_file(self,file_id)

	f_offset_modifier = 0

	if(massive != None):
		real_size = int(massive['fmeta']['size'])
		file_meta['name'] = massive['fmeta']['name']
		base_mod = int(massive['chunk_info']['name'].split("_")[-1])
		base_mod-=1
		f_offset_modifier = base_mod * massive['fmeta']['massive_chunk_size']

	total_size = int(file_meta['size'])
	url = 'https://api.onedrive.com/v1.0/drive/items/%s/content' % file_id
	current_offset = 0



	last_round = 0
	while current_offset < total_size:
		chk_sz = DOWNLOAD_CHUNK_SIZE - 1
		if(current_offset+chk_sz > total_size):
			chk_sz = total_size - current_offset
			last_round = 1
		#Check for Errors and repeat if issue.
		response = 999
		while response > 399:
			access_check(self)
			headers = {
			"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
			'Range':'bytes=%d-%d' % (current_offset,current_offset+chk_sz)
			}
			
			      		
			r = requests.get(url,headers=headers)

			data = r.content
			response = r.status_code
		

			if response > 399:
				print("large_download err: %d" % r.status_code)
				print(r.content)        
				time.sleep(5)
		#Decrypt Data if Encrypted
		if(self.client_config.get('encryption','aes_key') != ""):
			fmeta = stat_file(self,file_id)




			data = decrypt_block(self,data) 

		if(self.client_config.getboolean('download', 'multiproc_download_large') == True and in_daemon == False):
			rf_offset = int(current_offset+f_offset_modifier)
			q.put((rf_offset,data))			
			if(self.client_config.getboolean('rest','rest_callbacks') != False):
				gf = requests.get("%s/download_progress?chk_sz=%s" % (self.client_config.get('rest','rest_callback_url'),str(len(data))))
			current_offset+=chk_sz+1
		else:
			if(os.path.exists(out_path)):
				f = open(out_path,'rb+')
			else:
				f = open(out_path,'wb')
			f.seek(current_offset+f_offset_modifier,0)
			f.write(data)
			f.close()
			current_offset+=chk_sz+1
			if(massive == None):
				print("%s - %s/%s" % (file_meta['name'],sizeof_fmt(current_offset),sizeof_fmt(total_size)))
			else:
				augmented_offset = massive['file_progress'] + current_offset
				print("%s - %s/%s" % (file_meta['name'],sizeof_fmt(augmented_offset),sizeof_fmt(real_size)))
			if(self.client_config.getboolean('rest','rest_callbacks') != False):
				gf = requests.get("%s/download_progress?chk_sz=%s" % (self.client_config.get('rest','rest_callback_url'),str(chk_sz+1)))




	


def download_file_small(self,out_path,file_id):
	url = 'https://api.onedrive.com/v1.0/drive/items/%s/content' % file_id
	#Check for Errors and repeat if issue.
	response = 0
	while response != 200 and response != 302:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}

		r = requests.get(url,headers=headers)

		data = r.content
		response = r.status_code
		if response != 200:
			print("small_download err: %d" % r.status_code)
			print("file id:%s" % file_id)
			print("url: %s" % url)
			print(r.content)

	#Write file to disk.
	f = open(out_path,'wb')
	#Decrypt Data if Encrypted
	if(self.client_config.get('encryption','aes_key') != ""):
		fmeta = stat_file(self,file_id)

		data = decrypt_block(self,data)
	f.write(data)
	f.close()


'''
==========================
 FS Functions
==========================
'''
#Sends file to recycle bin.
def trash_file(self,file_id):
	#Short Circuit for 'Massive' Files...
	if('_massive' in file_id):
		#Get info for root file.
		fmeta = stat_file(self,file_id.split("_massive")[0])
		parent_id = fmeta['parentReference']['id']
		base_name = fmeta['name'][:fmeta['name'].rfind("_")]
		chunk_list = find(self,parent_id=parent_id,q='%s*' % base_name,massive='YES')
		for entry in chunk_list:
			trash_file(self,entry['id'])
		return

	url = 'https://api.onedrive.com/v1.0/drive/items/%s' % file_id
	#Check for Errors and repeat if issue.
	response = 0
	while response != 204:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
		r = requests.delete(url,headers=headers)   
		response = r.status_code
		if response != 204:
			print("trash_file err: %d" % r.status_code)

#Restores item from recycle bin.
def untrash_file(self,file_id):
	print("TODO - Doesn't Work Yet. Get your shit together, Microsoft...")
	return
	#Get file info
	info = stat_file(self,file_id)
	print(info)
	exit(1)
	#Set deleted to false.

	#Commit

#Permanently Deletes Item
def remove_file(self,file_id):
	print("TODO - remove_file not implemented.")
	return

#Standard directory listing with optional path and file parameter.
def ls(self,parent_id=None,massive=None):
	results = []
	success_codes = [200]
	if(parent_id == None):
		url = 'https://api.onedrive.com/v1.0/drive/root/children'
	else:
		url = 'https://api.onedrive.com/v1.0/drive/items/%s/children' % parent_id

	payload = {'top':200} # 200 results is the hard api limit
	response = 0
	while not response in success_codes:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
		r = requests.get(url,params=payload,headers=headers)
		response = r.status_code
		if(not r.status_code in success_codes):
			print("ls_err: %d" % r.status_code)
			print(r.content)

	results.extend(r.json()['value'])

	#Get all pages of results.
	while('@odata.nextLink' in r.json().keys()):
		skip_token = r.json()['@odata.nextLink'].split('skiptoken=')[1]
		payload['skiptoken'] = skip_token
		response = 0
		while not response in success_codes:
			access_check(self)
			headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
			r = requests.get(url, params=payload,headers=headers)
			response = r.status_code
			if(not r.status_code in success_codes):
				print("ls_err: %d" % r.status_code)
				print(r.content)

		results.extend(r.json()['value'])
	
	#Add support for Encrypted Entries.
	if(self.client_config.get('encryption','aes_key') != ""):
		results_tmp = []
		for i in range(0,len(results)):
			if(results[i]['name'].endswith(".jcf")):
				#Test Description Decrypt and if yes, change name, hash, and add it
				if("file" in results[i].keys()):
					desc = jcf_decrypt_description_hash(self,results[i]['description'])
					if(desc != "ERR"):

						results[i]['file']['hashes']['sha1Hash'] = desc.upper()
						dec_fname = decrypt_str(self,results[i]['name'])
						
						results[i]['name'] = dec_fname
						results_tmp.append(results[i])
					else:
						continue # Wrong key - we're gonna skip that file.
				else:
					#Directory PRocessing
					if(results[i]['name'].endswith(".jcf")):
						dec_fname = decrypt_str(self,results[i]['name'])
						results[i]['name'] = dec_fname
						results_tmp.append(results[i])

			else:
				results_tmp.append(results[i])
		results = results_tmp

	#Adjust 'Massive' Entries
	if(massive == None):
		results_tmp = []
		massive_entries = {}
		for i in range(0,len(results)):
			if(".jmf_" in results[i]['name']):

				#Strip to real name
				real_name = results[i]['name'].split(".jmf_")[0]
				#Get massive file hash.
				mfhash_index_1 = results[i]['name'].rfind("_")
				mfhash_index_0 = results[i]['name'].rfind("_", 0, mfhash_index_1) + 1
				mfhash = results[i]['name'][mfhash_index_0:mfhash_index_1]

				if(real_name not in massive_entries.keys()):
					massive_entries[real_name] = {
					'id':'',
					'name':real_name,
					'size':'0',
					'file':{'hashes':{'sha1Hash':mfhash}},
					'chunks':[]
					}
					 
				if(results[i]['name'].endswith('001')):
					massive_entries[real_name]['id'] = "%s_massive" % results[i]['id']
				tmp_sz = int(massive_entries[real_name]['size'])
				tmp_sz += int(results[i]['size'])
				massive_entries[real_name]['size'] = str(tmp_sz)
				massive_entries[real_name]['chunks'].append({
					'id':results[i]['id'],
					'file':{'hashes':{'sha1Hash':results[i]['file']['hashes']['sha1Hash']}},
					'part':int(results[i]['name'].split("_")[-1])
					})
			else:
				results_tmp.append(results[i])

		for me in massive_entries.keys():
			results_tmp.append(massive_entries[me])

		results = results_tmp				 

	return results

def find(self,parent_id=None,q='*',massive=None):    
	results = []
	success_codes = [200]
	if(parent_id == None):
		url = 'https://api.onedrive.com/v1.0/drive/root/view.search?q=%s' % q
	else:
		url = 'https://api.onedrive.com/v1.0/drive/items/%s/view.search?q=%s' % (parent_id,q)
 
	payload = {
	'top':50 # HARD API LIMIT
	}
	response = 0
	while not response in success_codes:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
		r = requests.get(url,params=payload,headers=headers)
		response = r.status_code
		if(not r.status_code in success_codes):
			print("find_err: %d" % r.status_code)
			print(r.content)

	results.extend(r.json()['value'])

	#Get all pages of results.
	while('@odata.nextLink' in r.json().keys()):
		skip_token = r.json()['@odata.nextLink'].split('skiptoken=')[1]
		payload['skiptoken'] = skip_token
		response = 0
		while not response in success_codes:
			access_check(self)
			headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
			r = requests.get(url, params=payload,headers=headers)
			response = r.status_code
			if(not r.status_code in success_codes):
				print("ls_err: %d" % r.status_code)
				print(r.content)

		results.extend(r.json()['value'])

	#Adjust 'Massive' Entries
	if(massive == None):
		results_tmp = []
		massive_entries = {}
		for i in range(0,len(results)):
			if(".jmf_" in results[i]['name']):
				#Strip to real name
				real_name = results[i]['name'].split(".jmf_")[0]
				if(real_name not in massive_entries.keys()):
					massive_entries[real_name] = {
					'id':'',
					'name':real_name,
					'size':'0',
					'chunks':[]
					}
					 
				if(results[i]['name'].endswith('001')):
					massive_entries[real_name]['id'] = "%s_massive" % results[i]['id']

				tmp_sz = int(massive_entries[real_name]['size'])
				tmp_sz += int(results[i]['size'])
				massive_entries[real_name]['size'] = str(tmp_sz)
				massive_entries[real_name]['chunks'].append({
					'id':results[i]['id'],
					'file':{'hashes':{'sha1Hash':results[i]['file']['hashes']['sha1Hash']}},
					'part':int(results[i]['name'].split("_")[-1])
					})
			else:
				results_tmp.append(results[i])
		for me in massive_entries.keys():
			results_tmp.append(massive_entries[me])
		
		results = results_tmp				 

	return results

#Add file description
def add_description(self,file_id,description):
	#TODO - Add MASSIVE support.
	url = 'https://api.onedrive.com/v1.0/drive/items/%s' % file_id
	response = 0
	while response != 200:
		access_check(self)
		headers = {
			"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
			"Content-Type": "application/json"
			}
		payload={
		"description":description
		}
		r = requests.patch(url,headers=headers,data=json.dumps(payload))		
		response = r.status_code
		if(response != 200):
			print("add_description err: %d" % response)
			print(r.content)
	return r.json()	

#Get item information.
def stat_file(self,file_id):
	#Hack to return part 1 for now...
	if('_massive' in file_id):
		file_id = file_id.split("_massive")[0]

	url = 'https://api.onedrive.com/v1.0/drive/items/%s' % file_id
	response = 0
	while response != 200:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
		r = requests.get(url,headers=headers)		
		response = r.status_code
		if(response != 200):
			print("stat_file err: %d" % response)
			print(r.content)
	fmeta = r.json()
	#Added AES
	if(self.client_config.get('encryption','aes_key') != ""):

		if(fmeta['name'].endswith(".jcf")):

			#Decrypt File Metadata
			if('file' in fmeta.keys()):
				desc = jcf_decrypt_description_hash(self,fmeta['description'])
				if(desc != "ERR"):
					fmeta['file']['hashes']['sha1Hash'] = desc.upper()
					fmeta['name'] = decrypt_str(self,fmeta['name'])

			else:
				fmeta['name'] = decrypt_str(self,fmeta['name'])

	return fmeta

#Move a file to a new parent.
def move_file(self,file_id,parent_id):
	#Short Circuit for 'Massive' Files...
	if('_massive' in file_id):
		#Get info for root file.
		fmeta = stat_file(self,file_id.split("_massive")[0])
		old_parent_id = fmeta['parentReference']['id']
		base_name = fmeta['name'][:fmeta['name'].rfind("_")]
		chunk_list = find(self,parent_id=old_parent_id,q='%s*' % base_name,massive='YES')
		for entry in chunk_list:
			move_file(self,entry['id'],parent_id)
		return
	url = 'https://api.onedrive.com/v1.0/drive/items/%s' % file_id
	response = 0
	while response != 200:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
		'Content-Type': 'application/json; charset=UTF-8'
		}
		body = {
  			"parentReference": {
    		"id": parent_id
    		}
		}
		r = requests.patch(url,headers=headers,data=json.dumps(body))		
		response = r.status_code
		if(response != 200):
			print("move_file err: %d" % response)
			print(r.content)
	return r.json()
	
#Rename file.
def rename_file(self,file_id,new_filename):
	#Short Circuit for 'Massive' Files...
	if('_massive' in file_id):
		#Get info for root file.
		fmeta = stat_file(self,file_id.split("_massive")[0])
		old_parent_id = fmeta['parentReference']['id']
		base_name = fmeta['name'][:fmeta['name'].rfind("_")]
		chunk_list = find(self,parent_id=old_parent_id,q='%s*' % base_name,massive='YES')
		for entry in chunk_list:
			new_massive_filename = "%s.jmf_%s" % (new_filename,entry['name'].split(".jmf_")[1])
			rename_file(self,entry['id'],new_massive_filename)
			
		return

	url = 'https://api.onedrive.com/v1.0/drive/items/%s' % file_id
	response = 0
	while response != 200:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
		'Content-Type': 'application/json; charset=UTF-8'
		}
		body = {
  			'name':new_filename
		}
		r = requests.patch(url,headers=headers,data=json.dumps(body))		
		response = r.status_code
		if(response != 200):
			print("rename_file err: %d" % response)
			print(r.content)
	return r.json()
	
#Copy file and optionally rename the copy.
def copy_file(self,file_id,dest_parent_id,new_filename=None):
	#Short Circuit for 'Massive' Files...
	if('_massive' in file_id):
		#Get info for root file.
		fmeta = stat_file(self,file_id.split("_massive")[0])
		old_parent_id = fmeta['parentReference']['id']
		base_name = fmeta['name'][:fmeta['name'].rfind("_")]
		chunk_list = find(self,parent_id=old_parent_id,q='%s*' % base_name,massive='YES')
		for entry in chunk_list:
			if(new_filename != None):
				new_massive_filename = "%s.jmf_%s" % (new_filename,entry['name'].split(".jmf_")[1])
				copy_file(self,entry['id'],dest_parent_id,new_massive_filename)
			else:
				copy_file(self,entry['id'],dest_parent_id,new_filename)
			
		return

	url = 'https://api.onedrive.com/v1.0/drive/items/%s/action.copy' % file_id
	response = 0
	while response != 202 and response != 303:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
		'Content-Type': 'application/json; charset=UTF-8',
		'Prefer': 'respond-async'
		}
		body = {
  			"parentReference": {
    		"id": dest_parent_id
    		}
		}
		#Add the replacement filename if needed.
		if(new_filename != None):
			body['name'] = new_filename

		r = requests.post(url,headers=headers,data=json.dumps(body))		
		response = r.status_code
		if(response != 202 and response != 303):
			print("copy_file err: %d" % response)
			print(r.content)
	return r.content

#Get a url for... reasons.
def get_url(self,file_id):
	return "https://onedrive.live.com/download.aspx?resid=%s" % file_id

#Create directory - no parent_id defaults to root directory.
def create_directory(self,folder_name,parent_id=None):
	url = ''
	if(parent_id != None):
		url = 'https://api.onedrive.com/v1.0/drive/items/%s/children' % parent_id
	else:
		url = 'https://api.onedrive.com/v1.0/drive/root/children'
	response = 999

	while response > 202:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
		'Content-Type':'application/json'
		}
		#Added AES
		if(self.client_config.get('encryption','aes_key') != ""):
			folder_name = generate_jcf_name(encrypt_str(self,folder_name))
		data = {
			"name": folder_name,
			"folder": { }
		}
		r = requests.post(url,data=json.dumps(data)+"  ",headers=headers)
		response = r.status_code
		if(r.status_code > 202):
			print("create_dir err %d" % r.status_code)
			print(r.content)
	return r.json()

'''
==========================
 Upload Functions
==========================
'''


#Master upload function; detours to other functions.
def upload_file(self,in_file,parent_id=None,file_split=None):
	try:
		self = dill.loads(self)
	except:
		pass
	fsz = os.path.getsize(in_file)
	start_time = time.time()
	frs = ""
	print("Uploading %s..." % os.path.split(in_file)[-1])
	if(file_split != None and os.path.getsize(in_file) > file_split * MB):
		upload_file_massive(self,in_file,parent_id,file_split)
	elif(fsz > MASSIVE_CHUNK_SIZE):
		frs = upload_file_massive(self,in_file,parent_id)
	elif(fsz > 50*(1024*1024)):
		frs = upload_file_large(self,in_file,parent_id)
	else:
		frs = upload_file_small(self,in_file,parent_id)
	elapsed_time = time.time() - start_time


		
	print("%s Upload Finished @ %s/sec" % (os.path.split(in_file)[-1],sizeof_fmt(fsz/elapsed_time)))
	return frs
#Upload file greater than 10GB limit.
def upload_file_massive(self,in_file,parent_id=None,file_split=None,in_daemon=True):

	base_filename = os.path.basename(in_file)
	#Get Adler32 Hash of file.
	print("Hashing  - Please Wait...")
	file_hash = get_sha1sum(in_file).upper()
	if(file_split == None):
		file_split = MASSIVE_CHUNK_SIZE
	output_filename = "%s.jmf_%d_%s_" % (base_filename,file_split,file_hash)
	file_split = file_split * MB
	
	total_size = os.path.getsize(in_file)

	file_parts = []
	cur_part = 0
	
	for i in range(0,total_size,file_split):
		if(i + file_split > total_size):
			
			remaining = total_size - i
			new_range = (i,i+remaining)
			cur_part +=1
			file_parts.append({
				'name':"%s%03d" % (output_filename,cur_part),
				'byte_range':new_range
				})	
		else:
			new_range = (i,i+file_split)
			cur_part +=1
			file_parts.append({
				'name':"%s%03d" % (output_filename,cur_part),
				'byte_range':new_range
				})
	slf = dill.dumps(self)
	file_progress = 0
	#Weed out parts that are already added.
	rdir_entries = ls(self,parent_id)
	for i in range (0,len(file_parts)):
		for rl in rdir_entries:
			if(rl['name'] == file_parts[i]['name']):
				file_progress+=(int(file_parts[i]['byte_range'][1]) - int(file_parts[i]['byte_range'][0]))
				file_parts.pop(i)

	if(in_daemon==False and self.client_config.getboolean('upload', 'multiproc_upload') == True):
		manager = mp.Manager()
		slf = dill.dumps(self)
		pool = mp.Pool(processes=self.client_config.getint('upload','multiproc_upload_maxprocs'))
		jobs = []
		
		for fl in file_parts:
			kwargs = {'parent_id':parent_id,'byte_range':fl['byte_range'],'output_filename':fl['name']}
			job = pool.apply_async(upload_file_large,(slf,in_file),kwargs)
			jobs.append(job)

		# collect results from the workers through the pool result queue
		for job in jobs: 
			job.get()

		pool.close()	

	else:
		for fl in file_parts:
			upload_file_large(self,in_file,parent_id=parent_id,byte_range=fl['byte_range'],output_filename=fl['name'])
			file_progress+=(int(fl['byte_range'][1]) - int(fl['byte_range'][0]))
		
#Upload file between 90MB and 10GB.
def upload_file_large(self,in_file,parent_id=None,byte_range=None,output_filename=None):
	real_size = os.path.getsize(in_file) #Used for massive file parts.
	try:
		self = dill.loads(self)
	except:
		pass

	max_chunk_sz = ((1024*1024) * 50)
	f_offset = 0
	f_modifier = 0
	if(byte_range == None):
		fsz = os.path.getsize(in_file)

	else:
		fsz = int(byte_range[1]) - int(byte_range[0])

		f_modifier = byte_range[0]
		fsz += f_offset

	url = ''
	
	last_round = 0
	fname = os.path.split(in_file)[1]
	if(output_filename != None):
		fname = output_filename

	#Encryption Addition.
	if(self.client_config.get('encryption','aes_key') != ""):
		fname = encrypt_str(self,fname)

	#Init Download
	if(output_filename==None):
		if(parent_id != None):
			url = 'https://api.onedrive.com/v1.0/drive/items/%s:/%s:/upload.createSession' % (parent_id,urllib.quote_plus(fname))
		else:
			url = 'https://api.onedrive.com/v1.0/drive/root:/%s:/upload.createSession' % (urllib.quote_plus(fname))
	else:
		if(parent_id != None):
			url = 'https://api.onedrive.com/v1.0/drive/items/%s:/%s:/upload.createSession' % (parent_id,urllib.quote_plus(fname))
		else:
			url = 'https://api.onedrive.com/v1.0/drive/root:/%s:/upload.createSession' % (urllib.quote_plus(fname))		
	response = 999
	while response != 200:
		access_check(self)
		headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
		up_session_url = ''
		r = requests.post(url,headers=headers)
		response = r.status_code
		if(r.status_code != 200):
			print("upload_file_large_1 err %d" % r.status_code)
			print(r.content)
			time.sleep(5)

	up_session_url = r.json()['uploadUrl']
	if(byte_range == None):
		print("Uploading %s %s" % (in_file,sizeof_fmt(fsz)))
	else:
		if(byte_range[0] == 0):
			print("Uploading %s %s" % (in_file,sizeof_fmt(real_size)))
	
	start_time = time.time()

	while(f_offset < fsz):
		chk_sz = max_chunk_sz
		if(fsz-f_offset < chk_sz):
			chk_sz = fsz-f_offset
			last_round = 1
		f=open(in_file,'rb')
		f.seek(f_offset+f_modifier)

		data = f.read(chk_sz)

		f.close()
		#AES ADDITION
		if(self.client_config.get('encryption','aes_key') != ""):
			data = encrypt_block(self,data)

		response = 999
		while response > 202:
			access_check(self)
			headers = {
			  "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
			  'Content-Range':'bytes %d-%d/%d' % (f_offset,(f_offset+chk_sz)-1,fsz)
			}

			r = requests.put(up_session_url,headers=headers,data=data)
			response = r.status_code
			if(r.status_code > 202):
				print("upload_file_large_2 err %d" % r.status_code)
				print(r.content)
				time.sleep(5)
			if(r.status_code == 416):
				print("%s Failed because of incomplete overlap - will retry..." % (in_file))
				return                    
		f_offset += chk_sz
		if(byte_range == None):
			print("%s Progress: %s/%s" % (in_file,sizeof_fmt(f_offset),sizeof_fmt(fsz)))
		else:
			print("%s Progress: %s/%s" % (in_file,sizeof_fmt(f_offset+f_modifier),sizeof_fmt(real_size)))
	elapsed_time = int(time.time() - start_time)

	#Encryption Addition.
	if(self.client_config.get('encryption','aes_key') != ""):

		description_hash = jcf_generate_description_hash(self,get_sha1sum(in_file))
		nf_id = r.json()['id']
		new_filename = generate_jcf_name(r.json()['name'])
		add_description(self,nf_id,description_hash)
		rename_file(self,nf_id,new_filename)

	if(fsz == real_size):
		print("%s Finished @ %s/sec" % (in_file,sizeof_fmt(fsz/elapsed_time)))
	return r.json()

def upload_file_small(self,in_file,parent_id=None):

	url = ''

	print("Starting upload of %s" % in_file)
	fsz = os.path.getsize(in_file)
	f = open(in_file,'rb')
	data = f.read()
	f.close()
	fname = os.path.split(in_file)[1]
	#Encryption Addition.
	if(self.client_config.get('encryption','aes_key') != ""):
		data = encrypt_block(self,data)
		fname = generate_jcf_name(encrypt_str(self,fname))
		description_hash = jcf_generate_description_hash(self,get_sha1sum(in_file))

			




	if(parent_id != None):
		url = 'https://api.onedrive.com/v1.0/drive/items/%s/children/%s/content' % (parent_id,urllib.quote_plus(fname))
	else:
		url = 'https://api.onedrive.com/v1.0/drive/root:/%s:/content' % (urllib.quote_plus(fname))		
	
	start_time = time.time()
	response = 400
	while response > 202:
		access_check(self)
		headers = {
		"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
		'Content-Type':'text/plain'
		}

		r = requests.put(url,headers=headers,data=data)
		response = r.status_code
		if(r.status_code > 202):
			print("upload_file err %d" % response)
			print(r.content)
			time.sleep(5)

	elapsed_time = time.time() - start_time
	print("%s Finished @ %s/sec" % (in_file,sizeof_fmt(fsz/elapsed_time)))

	#Encryption Description Addition.
	if(self.client_config.get('encryption','aes_key') != ""):
		nf_id = r.json()['id']
		add_description(self,nf_id,description_hash)

	return r.json()

#Upload a local directory recursively to root or parent_id.
def upload_directory(self,in_path,parent_id=None,file_split=None):
	while 1:
		dir_list = []
		file_list = []
		in_path = unicode(in_path)
		target_dir_id = ""

		#Find out if we have to make this directory.
		dir_listing = ls(self,parent_id)
		remote_dir_exists = False
		for dl in dir_listing:
			if(dl['name'] == os.path.basename(os.path.normpath(in_path))):
				remote_dir_exists = True
				target_dir_id = dl['id']
		print("Uploading directory: %s..." % in_path)
		
		if(remote_dir_exists == False):
			target_dir_id = create_directory(self,os.path.basename(os.path.normpath(in_path)),parent_id)['id']

		target_directory_list = ls(self,target_dir_id)

		target_directory_dict = {}
		for tdl in target_directory_list:

			if("file" in tdl):

				target_directory_dict[tdl['name']] = {'hash':tdl['file']['hashes']['sha1Hash'],
														'size':tdl['size']}

		for root,dirs,files in os.walk(unicode(in_path)):
			for d in dirs:
				dir_list.append(d)
			for f in files:
				file_path = os.path.join(root,f)
				
				if f in target_directory_dict.keys():
					print("%s found! Hashing local file, please wait..." % f)
					lhash = get_sha1sum(file_path).upper()

					if(lhash == target_directory_dict[f]['hash'] and os.path.getsize(file_path) == target_directory_dict[f]['size']):
						continue
				file_list.append(file_path)
			break
		#Process Files.
		if(len(file_list) == 0):
			print(" %s -- Directory Upload Complete!" % os.path.basename(os.path.normpath(in_path)))
			break
		else:
			print("%s -- has %d files to Upload" % (os.path.basename(os.path.normpath(in_path)),len(file_list)))
		if(self.client_config.getboolean('upload', 'multiproc_upload') == False):
			for fl in file_list:
				upload_file(self,fl,target_dir_id,file_split=file_split)
		else:
			manager = mp.Manager()
			slf = dill.dumps(self)
			pool = mp.Pool(processes=self.client_config.getint('upload','multiproc_upload_maxprocs'))
			jobs = []
			
			for fl in file_list:
				kwargs = {'file_split':file_split}
				job = pool.apply_async(upload_file,(slf,fl,target_dir_id),kwargs)
				jobs.append(job)

			# collect results from the workers through the pool result queue
			try:
				for job in jobs: 
					job.get()

				pool.close()	
			except:
				pass
	#Process Directories.
	for dl in dir_list:
		upload_directory(self,os.path.join(in_path,dl),target_dir_id)

#Test Main Method
if(__name__=="__main__"):
    print("Test Starting...")

