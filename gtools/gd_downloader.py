'''
	Generic Google Drive Downloader
	Description: Give an id of any file/folder, and the script
	will download the file or the directory recursively.
	
	If any files exist with the same hash, it will skip them
	as well.
	
	Note: Requires pip install --upgrade google-api-python-client
'''

#Generic Imports
import os,sys
#My Imports
import gd_auth,gd_ops

def usage(msg=None):
	if(msg != None):
		print(msg)
	print("%s file/directory_id" % sys.argv[0])
	exit(1)

if(__name__=="__main__"):
	if(len(sys.argv) < 2):
		usage()
	if(len(sys.argv[1]) != 28):
		usage("ERR - Invalid file/directory_id")
	
	#Log In
	drive_service = gd_auth.drive_login()
	fl = gd_ops.get_file_by_id(drive_service,sys.argv[1])
	
	#Determine if it's a file or directory and download.
	if(fl['mimeType'] == "application/vnd.google-apps.folder"):
		gd_ops.download_dir(drive_service,fl)
	else:	
		fsmb = float(float(fl['fileSize']) / (1024*1024))
		print("Downloading %s (%.2fMB)..." % (fl['title'],fsmb))
		gd_ops.download_file(drive_service,fl)
	
	print("Done!")
