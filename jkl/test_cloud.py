'''
	Cloud Storage Testing Platform for libjkl by Professor BatteryShark
'''

import os,sys

import jkl

def usage():
	print("Usage: %s provider_config_file" % sys.argv[0])	
	exit(1)

if(__name__=="__main__"):
	if(len(sys.argv) < 2):
		usage()
	if(not os.path.exists(sys.argv[1])):
		usage()

	provider_config_file = sys.argv[1]
	storage = jkl.CloudStorage(provider_config_file)
	print(storage.ops.get_about(storage))

'''
[Crypto Example for onedrive]
First, you set a 16 byte AES key to your keyring (and an optional IV).
Until you clear this key, any directory you make or file you upload
will be encrypted with this key. This will not affect unencrypted files
or your ability to download other files or browse a directory of both unencrypted
and encrypted files - they look all the same to you because... transparency, remember.

storage.ops.set_current_aes_key(storage,"f333487b8ff847b70fc3d0dabd0bb8d9") #a test key

#Then, we upload a file and get the resultant file_id.
fid = storage.ops.upload_file(storage,'D:\\copyrighted_files.zip')['id']
	
#We can see the decrypted filename in this list.
cdir = storage.ops.ls(storage)
for entry in cdir:
	print("%s %s" % (entry['name'],entry['id']))
	
#We can re-download the file.
storage.ops.download_file(storage,'D:\\good_ver\\',fid)

#Then, we can change keys with set_current_aes_key or
storage.ops.clear_current_aes_key(storage)

#Clear the key and continue uploading unencrypted files.
'''	


