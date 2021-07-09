'''
	Generic Google Drive Uploader
	Description: Point to a directory and this script
	will upload that directory recursively to Google Drive. 
	
	If any files exist with the same hash, it will skip them
	as well.
	
	Note: Requires pip install --upgrade google-api-python-client
'''

#Generic Imports
import os,sys
#My Imports
import gd_auth,gd_ops

def usage():
	print("%s in_path" % sys.argv[0])
	exit(1)

if(__name__=="__main__"):
	if(len(sys.argv) < 2):
		usage()
	if(not os.path.exists(sys.argv[1])):
		usage()
	#Log In
	drive_service = gd_auth.drive_login()
	#Recurse through all files in local path and upload them to GDrive.
	gd_ops.upload_dir(drive_service,sys.argv[1])
	print("Done!")