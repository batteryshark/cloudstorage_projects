# jkl
jkl (prounounced 'jackal' or call it 'cranberry toothpaste' for all I care) is a multi-process back-end and my attempt to make a generic, cross-platform driver that works with major cloud services; starting with GDrive and OneDrive.

Unlike a number of libraries available, this one has a few distinctive features:
- Instead of using the SDKs, everything is done with straight up REST requests from scratch; like it should be.
- Multicore/Multiprocess support of downloads and uploads to finish jobs even faster.
- Multiprocess downloads of large files (download faster by downloading large files in chunks).
- The library supports REST callbacks in case you want to hook it up to a web frontend or another program.
- The library supports massive file sizes - up to 10TB per file on onedrive (Implemented) and theoretically 5PB per file on Google Drive.
- The library supports AES encryption options on uploads, directory traversal, and downloads to encrypt/decrypt names and data. (WIP for GDrive / Implemented for OneDrive)
- Connections have configurable files that allow the user to change process number options, turn on and off multicore, rest callback, etc.

Core functionality includes the normal stuff:
- Uploading/Downloading entire directories or individual files.
- Add custom metadata content to files/directories through 'description'.
- Remove,Trash,Untrash,Copy,Move, mkdir, etc.
- Get info about the store
- Find files
- List children in a directory
- Auth, Re-Auth

I'm continuing development, but seeing as mostly everything is there (barring encryption and 'massive' file support on GDrive as 5TB is already pretty ridiculous), it seems only right to give this an initial release.


#Dependencies
- Python 2.7.9+ (others get buggy)
- dill
- requests

#How-To
1. open onedrive_client_example.conf or gdrive_client_example.conf
2. paste your client_id and client_secret API codes from the google/onedrive api page.
3. run test_cloud.py, it will give you a url to login with
4. paste the code into the window - it will cache this id for future use.

#To-Do
1. Documentation: there are a ton of features.
2. AES encryption for files, directories
3. 'Massive' support for GDrive



