# -*- encoding: utf-8 -*-
'''
    GDrive Provider Driver for libjkl
    2015 Professor Batteryshark
'''
import os,sys,requests,hashlib,time,json,urllib,dill,traceback
import multiprocessing as mp


#Constants
DOWNLOAD_CHUNK_SIZE = 1024*1024*50 #50MB
MASSIVE_CHUNK_SIZE = 1024*1024*1024*1024*5 #5TB
MB = 1024*1024

AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URI = "https://www.googleapis.com/oauth2/v3/token"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
SCOPES = ["https://www.googleapis.com/auth/drive"]


'''
==========================
 Utility Functions
==========================
'''
# Hash a local file with block_size=2^25 or 32MB.
def get_md5sum(infile,byte_range=None, block_size=2 ** 25):
    f = open(infile, "rb")
    md5 = hashlib.md5()
    while True:
        if(byte_range != None):
            if(f.tell()+block_size > byte_range[1]):
                data = f.read(byte_range[1] - f.tell())
                md5.update(data)
                break
            else:
                data = f.read(block_size)
        else:
            data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    f.close()
    return md5.hexdigest()



# Return human-readable size.
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
    access_token = data['access_token']
    token_expiration = time.time() + data['expires_in']
    save_creds(self,access_token,self.client_config.get('session','refresh_token'),token_expiration)  # File Navigation Mechanisms

# Log In
def log_in(self):
    # Step 1 - Get Authorization
    params = {
        "client_id": self.client_config.get('client','client_id'),
        "scope": SCOPES,
        "response_type": 'code',
        "redirect_uri": REDIRECT_URI
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
        'content-type': 'application/x-www-form-urlencoded'
    }
    payload = {
        "redirect_uri": REDIRECT_URI,
        "client_id": self.client_config.get('client','client_id'),
        'grant_type': 'authorization_code',
        'client_secret': self.client_config.get('client','client_secret'),
        'code': response_code
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
    url = 'https://www.googleapis.com/drive/v2/about'
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
#Master Download Function - Detours to other functions.
def download_file(self,file_id,out_path,in_daemon=False):

    try:
        self = dill.loads(self)
    except:
        pass
    fmeta = stat(self,file_id)
    total_size = int(fmeta['fileSize'])
    print("Starting Download: %s %s" % (fmeta['title'],sizeof_fmt(total_size)))

    start_time = time.time()
    out_path = os.path.join(out_path,fmeta['title'])
    if('_massive' in file_id):
        pass # Not Implemented Yet.
    elif(total_size > DOWNLOAD_CHUNK_SIZE):
        if(self.client_config.getboolean('download','multiproc_download_large') == True):
            download_large_multiproc(self,file_id,out_path,self.client_config.getint('download','multiproc_download_large_maxprocs'))
        else:
            download_large(self,file_id,out_path,in_daemon=in_daemon) 
    else:
        download_small(self,file_id,out_path)
    elapsed_time = time.time() - start_time
    print("%s Finished @ %s/sec" % (out_path,sizeof_fmt(int(total_size)/elapsed_time)))


#Small Downloads (<90MB) to file or memory or file - optional byte range.
def download_small(self,file_id,out_path=None,byte_range=None,q=None):
    url = 'https://www.googleapis.com/drive/v2/files/%s?alt=media' % file_id
    response = 999
    while response != 200:
        access_check(self)
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
        params={}
        if(byte_range != None):
            headers['Range']="bytes=%d-%d" % (byte_range[0],byte_range[1])
        r = requests.get(url,headers=headers,params=params)
        response = r.status_code
        if(response != 200):
            if(response == 403):
                #print("%s flagged as malware - bypassing abuse check..." % file_id)
                params['acknowledgeAbuse'] = True
                continue
            print('download small err: %d' % response)
            print(r.content)
            time.sleep(5)
    if(out_path!=None):
        if(q==None):
            f = open(out_path,'wb')
            f.write(r.content)
            f.close()
        else:
            q.put((byte_range[0],r.content))
        return None
    return r.content


#Downloads between 90MB and 5TB
def download_large(self,file_id,out_path,q=None,massive=None,in_daemon=True):
    try:
        self = dill.loads(self)
    except:
        pass

    if("_massive" in file_id):
        massive_file = True
        file_id = file_id.replace("_massive","")
    else:
        massive_file = False
    
    fmeta = stat(self,file_id)
    f_offset_modifier = 0
    if(massive != None):
        real_size = int(massive['fmeta']['fileSize'])
        fmeta['title'] = massive['fmeta']['title']
        base_mod = int(massive['chunk_info']['title'].split("_")[-1])
        base_mod-=1
        f_offset_modifier = base_mod * massive['fmeta']['massive_chunk_size']
   
    total_size = int(fmeta['fileSize'])
    url = 'https://www.googleapis.com/drive/v2/files/%s?alt=media' % file_id
    current_offset = 0       

    while current_offset < total_size:
        chk_sz = DOWNLOAD_CHUNK_SIZE
        if(current_offset+DOWNLOAD_CHUNK_SIZE > total_size):
            chk_sz = total_size - current_offset
        #Check for Errors and repeat if issue.
        response = 999
        while response > 399:
            access_check(self)
            headers = {
            "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
            'Range':'bytes=%d-%d' % (current_offset,current_offset+chk_sz)
            }
            params = {}
            r = requests.get(url,headers=headers,params=params)

            response = r.status_code
            if response > 399:
                if(response == 403):
                    #print("%s flagged as malware - bypassing abuse check..." % file_id)
                    params['acknowledgeAbuse'] = True
                    continue
                print("large_download err: %d" % r.status_code)
                print(r.content)        
                time.sleep(5)
        data = r.content
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
                print("%s - %s/%s" % (fmeta['title'],sizeof_fmt(current_offset),sizeof_fmt(total_size)))
            else:
                augmented_offset = massive['file_progress'] + current_offset
                print("%s - %s/%s" % (file_meta['title'],sizeof_fmt(augmented_offset),sizeof_fmt(real_size)))
            if(self.client_config.getboolean('rest','rest_callbacks') != False):
                gf = requests.get("%s/download_progress?chk_sz=%s" % (self.client_config.get('rest','rest_callback_url'),str(chk_sz+1)))
                                   

#Multiproc Chunk Listener Write Queue.
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

#Download file in multiple processes.
def download_large_multiproc(self,file_id,out_path,max_procs=5):
    file_meta = stat(self,file_id)
    total_size = int(file_meta['fileSize'])
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
        job = pool.apply_async(download_small,(slf,file_id),kwargs)
        jobs.append(job)

    # collect results from the workers through the pool result queue
    for job in jobs: 
        job.get()

    #now we are done, kill the listener
    q.put('kill')
    pool.close()       


#Downloads larger than 5TB because... idfk lol.
def download_massive(self,file_id,out_path,q=None,in_daemon=True):
    pass #I'll do this later - 5TB is pretty big...

#Download entire directory.
def download_directory(self,out_path,parent_id):

    parent_dir_meta = stat(self,parent_id)
    
    dir_listing = ls(self,parent_id)
    #Sanity-Check to ensure the id passed is actually a directory.
    if(parent_dir_meta['mimeType'] != 'application/vnd.google-apps.folder'):
        print("Given Parent ID is a file - downloading...")
        download_file(self,parent_id,out_path)
        return
    
    out_path = os.path.join(out_path,parent_dir_meta['title'])
    print("Downloading to %s..." % out_path)
    if(not os.path.exists(out_path)):
        os.makedirs(out_path)
    while 1:        
        #Files First
        file_bucket = []
        massive_file_bucket = []
        for item in dir_listing:
            if(item['mimeType'] != 'application/vnd.google-apps.folder'):
                if(os.path.exists(os.path.join(out_path,item['title']))):
                    lhash = get_md5sum(os.path.join(out_path,item['title'])).upper()
                    if(lhash == item['md5Checksum'].upper()):
                        continue
                if("_massive" in item['id']):
                    massive_file_bucket.append({'path':out_path,'id':item['id']})
                else:
                    file_bucket.append({'path':out_path,'id':item['id']})
        if(len(file_bucket) == 0 and len(massive_file_bucket) == 0):
            break
        if(self.client_config.getboolean('download','multiproc_download') == False):
            for fl in file_bucket:
                download_file(self,fl['path'],fl['id'])
        else:
            manager = mp.Manager()
            slf = dill.dumps(self)
            pool = mp.Pool(processes=self.client_config.getint('download', 'multiproc_download_maxprocs'))
            jobs = []
            for fl in file_bucket:
                kwargs = {'in_daemon':True}
                job = pool.apply_async(download_file,(slf,fl['id'],fl['path']),kwargs)
                jobs.append(job)
            
            for job in jobs: 
                job.get()
            pool.close() 

        for ml in massive_file_bucket:
            download_file(self,ml['id'],ml['path'],in_daemon=False)       

    #Then, we'll make directories and recurse.
    for item in dir_listing:
        if(item['mimeType'] == 'application/vnd.google-apps.folder'):
            download_directory(self,out_path,item['id'])

'''
==========================
 Upload Functions
==========================
'''
#Master Upload Function - Detours to other functions.
def upload_file(self,in_file,parent_id=None,file_split=None,in_daemon=False):
    try:
        self = dill.loads(self)
    except:
        pass

    fsz = os.path.getsize(in_file)
    start_time = time.time()
    print("Uploading %s..." % os.path.split(in_file)[-1])
    if(file_split != None and os.path.getsize(in_file) > file_split * MB):
        upload_massive(self,in_file,parent_id,file_split,in_daemon=in_daemon)
    elif(fsz > MASSIVE_CHUNK_SIZE):
        upload_massive(self,in_file,parent_id,in_daemon=in_daemon)
    elif(fsz > DOWNLOAD_CHUNK_SIZE):
        upload_large(self,in_file,parent_id)
    else:
        upload_small(self,in_file,parent_id)
    elapsed_time = time.time() - start_time
    print("%s Upload Finished @ %s/sec" % (os.path.split(in_file)[-1],sizeof_fmt(fsz/elapsed_time)))

#Upload small files (<90MB).
def upload_small(self,in_file,parent_id=None):
    url = 'https://www.googleapis.com/upload/drive/v2/files?uploadType=multipart'
    fsz = os.path.getsize(in_file)
    f = open(in_file,'rb')
    data = f.read()
    f.close()
    if(parent_id == None):
        parent_id = get_about(self)["rootFolderId"]
    file_meta = {'title':os.path.split(in_file)[1],'parents':[{"id":parent_id}]}
    response = 999
    while response != 200:
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
                'Content-Type': 'multipart/mixed; boundary="bundry"'
                }
        payload = "--bundry\nContent-Type: application/json; charset=UTF-8 \n\n"
        payload += json.dumps(file_meta)+"  \n\n--bundry\nContent-Type: application/octet-stream\n\n"
        payload += data+'\n'
        payload += "--bundry--\n"
        r = requests.post(url,headers=headers,data=payload)
        response = r.status_code
        if(response != 200):
            print('upload_small err:%d' % response)
            print(r.content)
            time.sleep(5)
    return r.json()

#Upload large files (90MB->5TB)
def upload_large(self,in_file,parent_id=None,byte_range=None,output_filename=None):
    real_size = os.path.getsize(in_file) #Used for massive file parts.
    try:
        self = dill.loads(self)
    except:
        pass
    max_chunk_sz = DOWNLOAD_CHUNK_SIZE
    f_offset = 0
    f_modifier = 0
    if(byte_range == None):
        fsz = os.path.getsize(in_file)
    else:
        fsz = int(byte_range[1]) - int(byte_range[0])
        f_modifier = byte_range[0]
        fsz += f_offset
    url = 'https://www.googleapis.com/upload/drive/v2/files?uploadType=resumable'

    #Init Download
    if(parent_id == None):
        parent_id = get_about(self)['rootFolderId']
    fname = os.path.split(in_file)[1]

    if(output_filename!=None):
        fname = output_filename
    file_meta = {'title':fname,'parents':[{"id":parent_id}]}
    
    response = 999
    while response != 200:
        access_check(self)
        headers = {
            "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
            'Content-Type': 'application/json; charset=UTF-8',
            'X-Upload-Content-Length':str(fsz)
        }

        r = requests.post(url,headers=headers,data=json.dumps(file_meta))
        response = r.status_code
        if(response != 200):
            print("upload_large_1 err: %d" % r.status_code)
            print(r.content)
            time.sleep(5)
    url = r.headers['location']
    success_code = [200,308]
    while(f_offset < fsz):
        chk_sz = DOWNLOAD_CHUNK_SIZE
        if(fsz-f_offset < max_chunk_sz):
            chk_sz = fsz-f_offset
        f=open(in_file,'rb')
        f.seek(f_offset+f_modifier)
        data = f.read(chk_sz)
        f.close()
        response = 999
        while not response in success_code:
            access_check(self)
            headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
            'Content-Range':'bytes %d-%d/%d' % (f_offset,(f_offset+chk_sz)-1,fsz)
            }
            r = requests.put(url,headers=headers,data=data)
            response = r.status_code
            if(not response in success_code):
                print("upload_large_2 err: %d" % r.status_code)
                print(r.content)
                if(r.status_code == 416):
                    print("%s Failed because of incomplete overlap - will retry..." % (in_file))
                    return
                time.sleep(5)
        f_offset += chk_sz
        if(byte_range == None):
            print("%s Progress: %s/%s" % (in_file,sizeof_fmt(f_offset),sizeof_fmt(fsz)))
        else:
            print("%s Progress: %s/%s" % (in_file,sizeof_fmt(f_offset+f_modifier),sizeof_fmt(real_size)))
    return r.json()



#Upload massive files (>5TB)
def upload_massive(self,in_file,parent_id=None,file_split=None,in_daemon=True):
    pass

#Upload Entire Directory.
def upload_directory(self,in_path,parent_id=None,file_split=None):
    while 1:
        dir_list = []
        file_list = []
        in_path = unicode(in_path)
        target_dir_id = ""
        #Find out if we have to make this directory.
        if(parent_id==None):
            parent_id = get_about(self)['rootFolderId']

        dir_listing = ls(self,parent_id)
        remote_dir_exists = False
        for dl in dir_listing:
            if(dl['title'] == os.path.basename(os.path.normpath(in_path))):
                if(dl['mimeType'] == 'application/vnd.google-apps.folder'):
                    if(dl['labels']['trashed'] == False):
                        remote_dir_exists = True
                        target_dir_id = dl['id']
        print("Uploading directory: %s..." % in_path)      
        if(remote_dir_exists == False):
            target_dir_id = mkdir(self,os.path.basename(os.path.normpath(in_path)),parent_id)['id']

        target_directory_list = ls(self,target_dir_id)
        target_directory_dict = {}
        for tdl in target_directory_list:
            if not 'application/vnd.google-apps.folder' in tdl['mimeType']:
                target_directory_dict[tdl['title']] = {'hash':tdl['md5Checksum'],
                                                        'size':tdl['fileSize']}
        for root,dirs,files in os.walk(unicode(in_path)):
            for d in dirs:
                dir_list.append(d)
            for f in files:
                file_path = os.path.join(root,f)                            
                if f in target_directory_dict.keys():
                    print("%s found! Hashing local file, please wait..." % f)
                    lhash = get_md5sum(file_path).upper()
                    if(lhash == target_directory_dict[f]['hash'].upper() and str(os.path.getsize(file_path)) == target_directory_dict[f]['size']):
    
                        continue
                    else:
                        file_list.append(file_path)
                else:
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

            for job in jobs:
                job.get()

            pool.close()

    #Process Directories.
    for dl in dir_list:
        upload_directory(self,os.path.join(in_path,dl),target_dir_id)


'''
==========================
 FS Functions
==========================
'''
#Sends files to the trash.
def trash(self,file_id,untrash=False):
    if(untrash == False):
        url ="https://www.googleapis.com/drive/v2/files/%s/trash" % file_id
    else:
        url ="https://www.googleapis.com/drive/v2/files/%s/untrash" % file_id
    response = 999
    while response != 200:
        access_check(self)
        headers = {
        "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
        'content-type':'application/json'
        }
        r = requests.post(url,headers=headers)
        response = r.status_code
        if(response != 200):
            print("err trash: %d" % response)
            print(r.content)
            time.sleep(5)

    if(untrash == False):
        print("%s Deleted." % file_id)
    else:
        print("%s Restored." % file_id)


#Restores files from the trash.
def untrash(self,file_id):
    trash(self,file_id,untrash=True)

#Permanently removes a file - directory recursive... PLEASE BE CAREFUL.
def remove(self,file_id):
    url ="https://www.googleapis.com/drive/v2/files/%s" % file_id
    response=999
    while response != 204:
        access_check(self)
        headers = {
        "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
        'content-type':'application/json'
        }
        r = requests.delete(url,headers=headers)
        response = r.status_code
        if(response != 204):
            print("err remove: %d" % response)
            print(r.content)
            time.sleep(5)
    print('%s Removed.' % file_id)      

#Move a file from one location to another.
def mv(self,file_id,parent_id=None,new_filename=None):
    #TODO - ADD MASSIVE MOVE AND RENAME.
    #Get item info.
    fmeta = stat(self,file_id)
    #Move to another parent if requested.
    if(parent_id != None):
        fmeta['parents'] = [{'id':parent_id}]

    #Rename item if requested.
    if(new_filename!=None):
        fmeta['title'] = new_filename
    #Commit Changes.
    url = 'https://www.googleapis.com/drive/v2/files/%s' % file_id
    response = 999
    while response != 200:
        access_check(self)
        headers = {
        "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
        'content-type':'application/json'
        }
        r = requests.put(url,data=json.dumps(fmeta),headers=headers)
        response = r.status_code
        if(r.status_code != 200):
            print("mv err: %d"% r.status_code)
            print(r.content)
            time.sleep(5)


#Copy file to another directory.
def cp(self,file_id,dest_parent_id=None,new_filename=None):
    fmeta = stat(self,file_id)
    if(new_filename != None):
        fmeta['title'] = new_filename
    if(dest_parent_id != None):
        fmeta['parents'] = [{"id":dest_parent_id}]   
    url = 'https://www.googleapis.com/drive/v2/files/%s/copy' % file_id
    response = 999
    while response != 200:
        access_check(self)
        headers = {
        "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
        'content-type':'application/json'
        }        
        r = requests.post(url,data=json.dumps(fmeta),headers=headers)
        response = r.status_code
        if(response != 200):
            print("copy err: %d" % r.status_code)
            print(r.content)
            time.sleep(5)


#Get url for direct access.
def get_url(self,file_id):
    return "https://googledrive.com/host/%s" % file_id

#Make directory.
def mkdir(self,name,parent_id=None):
    url = 'https://www.googleapis.com/drive/v2/files'
    if(parent_id == None):
        parent_id = get_about(self)['rootFolderId']
    
    data = {
        "title":name,
        "mimeType":"application/vnd.google-apps.folder",
        "parents":[{"id":parent_id}]
    }
    response = 999
    while response != 200:
        access_check(self)
        headers = {
        "Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
        'content-type':'application/json'
        }       
        r = requests.post(url,data=json.dumps(data),headers=headers)
        response = r.status_code
        if response != 200:
            print('mkdir err %d' % response)
            print(r.content)
            time.sleep(5)
    return r.json()


#Lists a directory's children.
def ls(self,parent_id=None,show_massive_chunks=False):
    results = []
    url = 'https://www.googleapis.com/drive/v2/files'
    if(parent_id == None):
        parent_id = get_about(self)["rootFolderId"]
    response = 999
    while response != 200:
        access_check(self)
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
        params = {'q':"'%s' in parents" % parent_id}
        r = requests.get(url,params=params,headers=headers)
        response = r.status_code
        if(response != 200):
            print('ls err: %d' % response)
            print(r.content)
            time.sleep(5)
    data = r.json()
    results.extend(data['items'])
    while('nextPageToken' in data.keys()):
        skip_token = data['nextPageToken']
        response = 999
        while response != 200:
            access_check(self)
            headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
            params = {'pageToken':skip_token,'q':"'%s' in parents" % parent_id}
            r = requests.get(url,params=params,headers=headers)
            response = r.status_code
            if(response != 200):
                print('ls err: %d' % response)
                print(r.content)
                time.sleep(5)     
            data = r.json()
            results.extend(data['items'])
    return results




#Searches for a file.
def find(self,parent_id=None,query=None,notshared=None,hidden=None,show_massive_chunks=False):
    results = []
    url = 'https://www.googleapis.com/drive/v2/files'
    response = 999
    query_str = ""
    if(query != None):
        query_str += "fullText contains \"%s\"" % query
    if(parent_id!=None):
        if(query_str!=""):
            query_str+=" and "
        query_str+="'%s' in parents" % parent_id
    if(notshared != None):
        if(query_str != ""):
            query_str+=" and sharedWithMe = false"
        else:
            query_str+="!sharedWithMe"
    if(hidden != None):
        if(query_str != ""):
            query_str+=" and hidden = true"
        else:
            query_str+="hidden = true"
            
    while response != 200:
        access_check(self)
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
        params = {'q':query_str}
        
        r = requests.get(url,params=params,headers=headers)
        response = r.status_code
        if(response != 200):
            print('ls err: %d' % response)
            print(r.content)
            time.sleep(5)
    data = r.json()
    
    results.extend(data['items'])
    while('nextPageToken' in data.keys()):
        skip_token = data['nextPageToken']
        response = 999
        while response != 200:
            access_check(self)
            headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
            params = {'pageToken':skip_token,'q':query_str}
            r = requests.get(url,params=params,headers=headers)
            response = r.status_code
            if(response != 200):
                print('ls err: %d' % response)
                print(r.content)
                time.sleep(5)     
            data = r.json()
            results.extend(data['items'])
    return results



def stat(self,file_id):
    #Massive Patch for now...
    if('_massive' in file_id):
        file_id = file_id.split("_massive")[0]
    url = 'https://www.googleapis.com/drive/v2/files/%s' % file_id
    response = 0
    while response != 200:
        access_check(self)
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token')}
        params = {'acknowledgeAbuse':True}
        r = requests.get(url,headers=headers,params=params)
        response = r.status_code
        if(response != 200):
            print("stat err: %d" % response)
            print(r.content)
            time.sleep(5)
    return r.json()

def add_description(self,file_id,description):
    #Massive Patch for now...
    if('_massive' in file_id):
        file_id = file_id.split("_massive")[0]
    fmeta = stat(self,file_id)
    fmeta['description'] = description
    url = 'https://www.googleapis.com/drive/v2/files/%s' % file_id
    response = 0
    while response != 200:
        access_check(self)
        headers = {"Authorization":"Bearer %s" % self.client_config.get('session','access_token'),
        'Content-Type':'application/json'
        }
        
        r = requests.put(url,headers=headers,data=json.dumps(fmeta))
        response = r.status_code
        if(response != 200):
            print("add_description err: %d" % response)
            print(r.content)
            time.sleep(5)
    return r.json()

