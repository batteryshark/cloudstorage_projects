import jkl_globals,jkl_logging,jkl_rest,jkl_utils,json

import time,os

logger = jkl_logging.Log("Driver")

# Constants for Google Drive V3 API
AUTH_URI     = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URI    = "https://accounts.google.com/o/oauth2/token"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
REVOKE_URI   = "https://accounts.google.com/o/oauth2/revoke"
SCOPES       = ["https://www.googleapis.com/auth/drive"]
API_V3_ROOT  = "https://www.googleapis.com/drive/v3"

# For Caching
DIR_DB = {}
FILE_DB = {}
PERM_DB = {}

# All Google Drive API Specific Operations Handled Here.
class GoogleDrive(object):
    def __init__(self,config):
        self.type = "GoogleDrive"
        self.instance_nickname = config['nickname']
        self.cache_path = "%s_%s_cache.json" % (self.type,config['nickname'])
        self.logger = jkl_logging.Log("%s_%s" % (self.type, self.instance_nickname))
        # Load Cache config if it exists (for now).
        if(os.path.exists(self.cache_path)):
            self.load_cache_config()

        else:
            self.client_id = config['client_id']
            self.client_secret = config['client_secret']
            self.access_token = ""
            self.refresh_token = ""
            self.token_expiration = 0
            self.encryption_type = "AES256"
            self.encryption_mode = "CTR"
            self.multithreaded_download = False
            self.multithreaded_download_max = 9
            self.multithreaded_upload = False
            self.multithreaded_upload_max = 5
            self.max_attempts = 5
            self.chunk_size = 50 * jkl_globals.MB
            self.massive_size = 5 * jkl_globals.TB



        # Can't do a whole lot without first making sure we're authenticated, check at init.
        self.access_ok = False
        self.access_check()
        # Get Info from Account
        self.account_info = self.get_info()
        self.account_username = self.account_info['user']['emailAddress']
        self.root_folder_id = self.get_root_folder_id()
        self.permission_id = self.account_info['user']['permissionId']



    # Load from a specified config file.
    def load_cache_config(self):
        self.logger.DEBUG("Loading from a previous cache file...")

        with open(self.cache_path, "rb") as f:
            config_cache = json.load(f)
            # Update the other config items in cache.
            self.client_id = config_cache['client_id']
            self.client_secret = config_cache['client_secret']
            self.access_token = config_cache['access_token']
            self.refresh_token = config_cache['refresh_token']
            self.token_expiration = config_cache['token_expiration']
            self.chunk_size = config_cache['chunk_size']
            self.massive_size = config_cache['massive_size']
            self.encryption_type = config_cache['encryption_type']
            self.multithreaded_download = config_cache['multithreaded_download']
            self.multithreaded_download_max = config_cache['multithreaded_download_max']
            self.multithreaded_upload = config_cache['multithreaded_download']
            self.multithreaded_upload_max = config_cache['multithreaded_download_max']
            self.max_attempts = config_cache['max_attempts']


    def save_cache_config(self):
            cache_config = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'token_expiration': self.token_expiration,
                'chunk_size': self.chunk_size,
                'massive_size': self.massive_size,
                'encryption_type': self.encryption_type,
                'multithreaded_download': self.multithreaded_download,
                'multithreaded_download_max': self.multithreaded_download,
                'multithreaded_upload': self.multithreaded_upload,
                'multithreaded_max': self.multithreaded_upload,
                'max_attempts': self.max_attempts
            }
            with open(self.cache_path, "wb") as g:
                json.dump(cache_config, g)


    # Checks to see if the current token has expired or not available and calls to re-authenticate or log in.
    def access_check(self):

        if(self.refresh_token == ""):
            # We need to initially log in.
            self.access_ok = self.authenticate()
            if(self.access_ok == False):
                self.logger.FATAL("Could not authenticate.")
        elif((int(time.time()) > self.token_expiration)):
            self.access_ok = self.refresh_access_token()
            if(self.access_ok == False):
                self.access_ok = self.authenticate()
                if(self.access_ok == False):
                    self.logger.FATAL("Could not refresh the token or re-authenticate.")


    # Re-authenticates to generate a new OAUTH token.
    def authenticate(self):
        # Step 1 - Get Authorization
        params = {
            'client_id':self.client_id,
            'scope': SCOPES,
            'response_type':'code',
            'redirect_uri':REDIRECT_URI
        }

        access_request_url = ""

        for i in range(0,self.max_attempts):
            self.logger.DEBUG("Step 1: Authorization...")
            response = jkl_rest.do_get(AUTH_URI,params=params)
            if(response.status_code == jkl_rest.HTTP_OK):
                access_request_url = response.url
                break
            time.sleep(5)

        if(access_request_url == ""):
            self.logger.FATAL("Unable to Receive Authorization URL")
            return False

        self.logger.INFO("Go to This Link: %s" % access_request_url)
        authorization_code = raw_input("Paste Response Code:")

        # Step 2: Do the Authorization Electric Boogaloo
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        body = {
            "redirect_uri": REDIRECT_URI,
            "client_id": self.client_id,
            'grant_type': 'authorization_code',
            'client_secret': self.client_secret,
            'code': authorization_code
        }

        for i in range(0,self.max_attempts):
            self.logger.DEBUG("Step 2: Get Access Token")
            response = jkl_rest.do_post(TOKEN_URI,data=body,headers=headers)
            if(response.status_code == jkl_rest.HTTP_OK):
                data = json.loads(response.content)
                self.refresh_token = data['refresh_token']
                self.access_token = data['access_token']
                self.token_expiration = int(time.time()) + data['expires_in']
                self.save_cache_config()
                break


    # If we have a refresh token, use it, if it doesn't work, re-authenticate
    def refresh_access_token(self):
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        body = {
            'redirect_uri':REDIRECT_URI,
            'client_id':self.client_id,
            'grant_type':'refresh_token',
            'refresh_token':self.refresh_token,
            'client_secret':self.client_secret
        }

        for i in range(0,self.max_attempts):
            self.logger.DEBUG("Attempting to Refresh the Token...")
            response = jkl_rest.do_post(TOKEN_URI,headers=headers,data=body)
            if(response.status_code == jkl_rest.HTTP_OK):
                # Set everything.
                data = json.loads(response.content)
                self.access_token = data['access_token']
                self.token_expiration = int(time.time()) + data['expires_in']
                self.save_cache_config()
                return True
            time.sleep(5)

        return False

    # Get Storage Account Information
    def get_info(self):
        self.access_check()
        headers = {'Authorization':"Bearer %s" % self.access_token}
        params = {'fields': "kind,user,storageQuota"}

        for i in range(0,self.max_attempts):
            response = jkl_rest.do_get(API_V3_ROOT+"/about",headers=headers,params=params)
            if(response.status_code == jkl_rest.HTTP_OK):
                print(response.json())
                return response.json()
            else:
                self.logger.ERROR("get_info failed with status code %d" % response.status_code)
                # We shouldn't re-attempt if the request was bad, no point.
                if(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                    #print(response.content)
                    return {}
            time.sleep(5)

        return {}

    def get_root_folder_id(self):
        self.access_check()
        headers = {'Authorization':"Bearer %s" % self.access_token}
        params = {'fields':"id"}
        for i in range(0,self.max_attempts):
            response = jkl_rest.do_get(API_V3_ROOT+"/files/root",headers=headers,params=params)
            if(response.status_code == jkl_rest.HTTP_OK):
                return response.json()['id']

            if(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                self.logger.FATAL("Get Root Folder id failed because of a bad request.")
                #print(response.content)
                return ""
            time.sleep(5)

    def ls(self,parent_id=None):
        self.access_check()

        if(parent_id == None):
            parent_id = self.root_folder_id


        params = {
            'q':"'%s' in parents" % parent_id,
            'fields':'files,nextPageToken'
        }
        items_lst = []
        ls_complete = False
        next_page_token = None
        while ls_complete == False:
            # ls another page if the previous result said there were more items.
            if(next_page_token != None):
                params['pageToken'] = next_page_token

            for i in range(0,self.max_attempts):
                self.access_check()
                headers = {'Authorization': "Bearer %s" % self.access_token}
                response = jkl_rest.do_get(API_V3_ROOT+"/files",headers=headers,params=params)
                if(response.status_code == jkl_rest.HTTP_OK):
                    data = response.json()
                    #print(data)
                    for item in data['files']:
                        if(item['mimeType'] == "application/vnd.google-apps.folder"):
                            item_type = 'folder'
                        else:
                            item_type = 'file'

                        entry = {
                            'id': item['id'],
                            'name': item['name'],
                            'type': item_type,
                            'parents': item.get('parents', []),
                            'owners': item['owners'],
                            'size': item.get('size', 0),
                            'hash': item.get('md5Checksum', ""),
                        }

                        items_lst.append(entry)

                    # Break out of the loop if we're done.
                    if(not "nextPageToken" in data.keys()):
                        ls_complete = True

                    else:
                        next_page_token = data['nextPageToken']

                    break
                elif(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                    self.logger.FATAL("ls bad request")
                    print(response.content)
                    return False
                else:
                    self.logger.ERROR("ls errored with code %d" % response.status_code)
                time.sleep(5)


                if(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                    self.logger.FATAL("ls failed because of a bad request.")
                    print(response.content)
                    return ""
                time.sleep(5)
        DIR_DB[parent_id] = items_lst
        return items_lst

    def stat(self,object_id):
        self.access_check()

        headers = {'Authorization':"Bearer %s" % self.access_token}
        params = {'fields':"id,name,mimeType,md5Checksum,size,parents,owners"}
        for i in range(0,self.max_attempts):
            response = jkl_rest.do_get(API_V3_ROOT+"/files/%s" % object_id,headers=headers,params=params)
            if(response.status_code == jkl_rest.HTTP_OK):
                data = response.json()
                #print(data)
                if(data['mimeType'] == "application/vnd.google-apps.folder"):
                    item_type = 'folder'
                else:
                    item_type = 'file'
                file_info = {
                    'id': data['id'],
                    'name': data['name'],
                    'type':item_type,
                    'parents':data.get('parents',[]),
                    'owners':data['owners'],
                    'size':data.get('size',0),
                    'hash':data.get('md5Checksum',""),

                }
                FILE_DB[object_id] = file_info
                return file_info

            if(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                self.logger.FATAL("Get Root Folder id failed because of a bad request.")
                #print(response.content)
                return ""
            print("Stat Returned Code: %d" % response.status_code)
            time.sleep(5)

    # Revokes current access (will need to re-authenticate after this).
    def revoke_oauth(self):
        pass #TODO, actual logic.


    def get_object_permissions(self,object_id):
        if(object_id in PERM_DB.keys()):
            return PERM_DB[object_id]
        self.access_check()
        headers = {'Authorization': "Bearer %s" % self.access_token}

        for i in range(0,self.max_attempts):
            response = jkl_rest.do_get(API_V3_ROOT+"/files/%s/permissions" % object_id,headers=headers)
            if(response.status_code == jkl_rest.HTTP_OK):
                data = response.json()
                permission_db = {}
                for item in data['permissions']:
                    permission_db[item['id']] = item
                return permission_db

            elif(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                print(response.content)
                return {}

            else:
                self.logger.ERROR("get_object_permissions failed with error: %d" % response.status_code)


            time.sleep(5)


    # Shares a given object with another account.
    def share_object(self,object_id,to_account_username):
        # POST https://www.googleapis.com/drive/v3/files/fileId/permissions
        self.access_check()
        headers = {'Authorization': "Bearer %s" % self.access_token}
        params = {'sendNotificationEmail':"False"}
        body = {
            'role':"reader",
            'type':"user",
            'emailAddress':to_account_username
        }
        for i in range(0,self.max_attempts):
            response = jkl_rest.do_post(API_V3_ROOT+"/files/%s/permissions" % object_id,params=params,json=body,headers=headers)
            if(response.status_code == jkl_rest.HTTP_OK):
                data = response.json()
                PERM_DB[object_id] = data
                return data
            elif(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                self.logger.FATAL("share_object bad request")
                print(response.content)
                return {}
            else:
                self.logger.ERROR("share_object error code: %d" % response.status_code)

            time.sleep(5)

    # Unshares a given object with another account.
    def unshare_object(self,object_id,permission_id):
        self.logger.INFO("Unsharing %s with %s" % (object_id,permission_id))
        self.access_check()
        headers = {'Authorization': "Bearer %s" % self.access_token}
        for i in range(0,self.max_attempts):
            response = jkl_rest.do_delete(API_V3_ROOT+"/files/%s/permissions/%s" % (object_id,permission_id),headers=headers)
            if(response.status_code == jkl_rest.HTTP_NO_CONTENT):
                return
            elif response.status_code == jkl_rest.HTTP_BAD_REQUEST:
                self.logger.FATAL("unshare_object bad request")
                print(response.content)
                return
            else:
                self.logger.ERROR("unshare_object error: %d" % response.status_code)

            time.sleep(5)

    def move_object(self,object_info,parent_id=None,rename=None):
        self.access_check()
        if(parent_id==None and rename==None):
            return False
        headers = {'Authorization': "Bearer %s" % self.access_token}
        params = {}
        if(parent_id != None):
            # Get Previous Parents
            previous_parents = object_info['parents']
            params['removeParents'] = previous_parents
            params['addParents'] = [parent_id]
        if(rename != None):
            params['name'] = rename


        for i in range(0,self.max_attempts):
            response = jkl_rest.do_put(API_V3_ROOT+"/files/%s" % object_info['id'],headers=headers,params=params)
            if(response.status_code == jkl_rest.HTTP_OK):
                return self.stat(response.json()['id'])
            elif(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                self.logger.FATAL("move_object bad request")
                print(response.content)
                return {}
            elif(response.status_code == jkl_rest.HTTP_NOTFOUND):
                continue
            else:
                self.logger.ERROR("move_object error code %d" % response.status_code)
                print(response.content)

            time.sleep(5)


    def copy_file(self,object_id,dest_parent):
        self.access_check()
        # Get some information about the original file.
        original_file_info = self.stat(object_id)

        new_file_info = {}
        #POST https://www.googleapis.com/drive/v3/files/fileId/copy
        headers = {'Authorization': "Bearer %s" % self.access_token}

        body = {
            'name':original_file_info['name'],
            'parents':[dest_parent]
        }
        exp_backoff = 10
        for i in range(0,self.max_attempts):
            response = jkl_rest.do_post(API_V3_ROOT+"/files/%s/copy" % object_id,headers=headers,json=body)
            if(response.status_code == jkl_rest.HTTP_OK):
                data = response.json()

                new_file_info = self.stat(data['id'])
                break

            elif(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                self.logger.FATAL("copy_file bad request")
                print(response.content)
                return False
            elif(response.status_code == jkl_rest.HTTP_UNAUTHORIZED):
                self.access_check()
            elif(response.status_code == jkl_rest.HTTP_FORBIDDEN):
                if("usageLimits" in response.content):
                    print("Cooling down...")
                    time.sleep(300) # 5
                    print("Restarting...")
            else:
                self.logger.ERROR("copy_file error code: %d" % response.status_code)
                print(response.content)

            time.sleep(exp_backoff*i)

        if(new_file_info == {}):
            return False

        # Move the file to the proper parent.
        #return self.move_object(new_file_info,parent_id=dest_parent)


    def delete_object(self,object_id):
        self.access_check()
        headers = {'Authorization': "Bearer %s" % self.access_token}
        for i in range(0,self.max_attempts):
            response = jkl_rest.do_delete(API_V3_ROOT+"/files/%s" % object_id,headers=headers)
            if(response.status_code == jkl_rest.HTTP_NO_CONTENT):
                return True
            else:
                self.logger.ERROR("delete_object err: %d" % response.status_code)
            time.sleep(5)
        return False

    def prune_duplicates(self,parent_id):
        self.access_check()
        # Get list of all files in target
        keep_lst = []
        rem_lst = []
        obj_lst = self.ls(parent_id)
        for entry in obj_lst:
            keep = 1
            for oc in keep_lst:
                if(oc['name'] == entry['name'] and oc['hash'] == entry['hash']):
                    rem_lst.append(entry)
                    keep = 0
                    break
            if(keep == 1):
                keep_lst.append(entry)
        print("%d Duplicates to Remove" % len(rem_lst))
        # Delete everything in rem_lst
        for entry in rem_lst:
            print("Deleting Duplicate %s..." % entry['name'])
            self.delete_object(entry['id'])

    def create_directory(self,name,parent_id):
        self.access_check()
        headers = {'Authorization': "Bearer %s" % self.access_token}
        body = {
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
            'parents':[parent_id]
        }

        # Check if the directory exists - info and skip if so.
        obj_lst = self.ls(parent_id)

        for item  in obj_lst:
            if(item['name'] == name):
                self.logger.INFO("Create directory '%s' Skipped - Exists" % name)
                object_info = item
                if(object_info['type'] != 'folder'):
                    self.logger.FATAL("Object %s is a file, a directory creation was attempted." % name)
                    return False
                return object_info

        for i in range(0,self.max_attempts):
            response = jkl_rest.do_post(API_V3_ROOT+"/files",headers=headers,json=body)
            if(response.status_code == jkl_rest.HTTP_OK):
                return self.stat(response.json()['id'])
            elif(response.status_code == jkl_rest.HTTP_BAD_REQUEST):
                self.logger.FATAL("create_directory bad request")
                print(response.content)
                return False
            else:
                self.logger.ERROR("create_directory returned %d" % response.status_code)

            time.sleep(5)

        return False



def migrate_file_slow(from_account,to_account,file_id,dest_path=None):
    # Save to root if no path given.
    if (dest_path == None):
        dest_path = to_account.root_folder_id


def migrate_file_direct(from_account,to_account,file_id,dest_path=None):
    # Save to root if no path given.
    if (dest_path == None):
        dest_path = to_account.root_folder_id


    # Get current permissions of the object.
    status = False
    permissions_db = from_account.get_object_permissions(file_id)
    permission_exists = False

    # Temporarily share the object if it wasn't shared already.
    if(to_account.permission_id in permissions_db.keys()):
        permission_exists = True
    else:
        status = from_account.share_object(file_id,to_account.account_username)


    # Make a copy of the file itself from the from_account to the to_account
    # First - check if file is there and skip
    # TODO: Remove after testing.
    #item_lst = to_account.ls(dest_path)
    #cf_item = from_account.stat(file_id)
    #print(item_lst)
    #print(cf_item)
    #for item in item_lst:
        #if(cf_item['name'] == item['name']):
            #logger.INFO("Duplicate file found in dest - skipping...")
            #return True

    status = to_account.copy_file(file_id,dest_path)

    # Unshare the file with to_account if it wasn't shared to begin with.
    #if(permission_exists == False):
    status = from_account.unshare_object(file_id,to_account.permission_id)

    return status





def migrate_directory_direct(from_account,to_account,source_root,dest_parent=None):
    # Save to root if no path given.
    if(dest_parent == None):

        dest_parent = to_account.root_folder_id


    parent_info = from_account.stat(source_root)
    # Step 1 - Create a directory and make that the new parent.
    n_parent_info = to_account.create_directory(parent_info['name'],dest_parent)
    # Step 2 - Get a list of all objects in the parent.
    root_lst = from_account.ls(source_root)

    # Step 2 and half - make sure you aren't copying duplicates because that's silly...
    nrl = []
    for entry in root_lst:
        dupe = False
        for e2 in nrl:
            if(e2['name'] == entry['name'] and e2['hash'] == entry['hash']):
                dupe = True
                break
        if(dupe == False):
            nrl.append(entry)
    root_lst = nrl


    # Step 3 - Get a lit of all objects in the destination (for duplicate skipping)
    dest_lst = to_account.ls(n_parent_info['id'])


    subdirectory_lst = []
    file_lst = []

    for entry in root_lst:
        if(entry['type'] == "folder"):
            subdirectory_lst.append(entry)
        else:
            file_lst.append(entry)
    # Step 4 - Carve dat shit up like a christmas goose - filter duplicates.
    n_file_lst = []
    for entry in file_lst:
        duplicate = False
        for e2 in dest_lst:
            if(e2['name'] == entry['name'] and e2['hash'] == entry['hash']):
                duplicate = True
                break
        if(duplicate == False):
            n_file_lst.append(entry)
    file_lst = n_file_lst
    print("%d Files to migrate in this directory." % len(file_lst))
    # Step 5 - Migrate all files (only files) - we might want to parallelize this part.
    for entry in file_lst:
        logger.INFO("Migrating %s..." % entry['name'])
        #print(entry)
        #print(n_parent_info)
        #migrate_file_direct(from_account,to_account,entry['id'],dest_path=n_parent_info['id'])
        migrate_file_slow(from_account,to_account,entry['id'],dest_path=n_parent_info['id'])
    # Step 4 - Iterate through all directories and pass them to this function.
    for entry in subdirectory_lst:
        migrate_directory_direct(from_account,to_account,entry['id'],dest_parent=n_parent_info['id'])



# Test Harness for GoogleDrive API Stuff
if(__name__=="__main__"):
    jkl_globals.init()
    personal_config = {
        'nickname'     : 'PersonalGDrive',
        'client_id'    : '84127604816-b83eaqf9j9bhmk550pb2r3barvnns0qj.apps.googleusercontent.com',
        'client_secret': 'l44ozZVKMHYmBwNp1ycZP98X'

    }
    #personal_drive = GoogleDrive(personal_config)

    deis_config = {
        'nickname': 'DeisGDrive',
        'client_id': '84127604816-b83eaqf9j9bhmk550pb2r3barvnns0qj.apps.googleusercontent.com',
        'client_secret': 'l44ozZVKMHYmBwNp1ycZP98X'

    }

    deis_drive = GoogleDrive(deis_config)
    #migrate_file_direct(deis_drive,personal_drive,"0B5cM_oMaeyO6TldBZXdkX1d0OEE")

    stonefish_config = {
        'nickname': 'StonefishGDrive',
        'client_id': '84127604816-b83eaqf9j9bhmk550pb2r3barvnns0qj.apps.googleusercontent.com',
        'client_secret': 'l44ozZVKMHYmBwNp1ycZP98X'

    }

    stonefish_drive = GoogleDrive(stonefish_config)


    #migrate_directory_direct(deis_drive,stonefish_drive,"0B5cM_oMaeyO6OUhabnZ5ZTJHZUU")

    #deis_drive.unshare_object("0B5cM_oMaeyO6QlM3RVprd3NlWjg", "00808307583840186349")
    #deis_drive.delete_object("0B5cM_oMaeyO6VXJHT3N4YXRTVk0")

    migrate_directory_direct(deis_drive,stonefish_drive,"0B5cM_oMaeyO6Q0RJUmh5UlUyNVk")
    #stonefish_drive.prune_duplicates("0BzM3L-z0co9WOWJ0NlFNTGszc28")

"""
Traceback (most recent call last):
  File "/Users/rfx/PycharmProjects/jkl_redux/jkl_providers/GoogleDrive/__init__.py", line 686, in <module>
    migrate_directory_direct(deis_drive,stonefish_drive,"0B5cM_oMaeyO6aldUcUFKWm9hOFU")
  File "/Users/rfx/PycharmProjects/jkl_redux/jkl_providers/GoogleDrive/__init__.py", line 643, in migrate_directory_direct
    migrate_file_direct(from_account,to_account,entry['id'],dest_path=n_parent_info['id'])
  File "/Users/rfx/PycharmProjects/jkl_redux/jkl_providers/GoogleDrive/__init__.py", line 576, in migrate_file_direct
    status = to_account.copy_file(file_id,dest_path)
  File "/Users/rfx/PycharmProjects/jkl_redux/jkl_providers/GoogleDrive/__init__.py", line 446, in copy_file
    'name':original_file_info['name'],
TypeError: 'NoneType' object has no attribute '__getitem__'
"""

"""
Operations
get_info:
    get_info_file
    get_info_directory
ls
mv
cp
trash - send file to trash
rm - delete file (WARNING - this will actually delete like for realsies)
download_directory
upload_directory
download_file
upload_file
    # Check for what the error is when you run out of space and fail.
    
migrate_file_direct (upper function) (basically copy a shared file to another directory after adding it to your drive)
    have to check to ensure the two provider caches are on the same service (e.g. can't migrate from onedrive to gdrive)

migrate_directory_direct (upper function) much like migrate file but migrates an entire tree (will be useful)
Todo: Fix bug where you keep redownloading a duplicate file because of the names (maybe flatten all names out)
"""