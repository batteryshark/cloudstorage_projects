'''
	PCSX2Cloud by BatteryShark
	A front-end for PCSX2 that browses your GoogleDrive shares for games that
	have been uploaded with the EmuCloud uploader (either by you or shared with you).
'''

import gc_auth,os,sys,shutil
from apiclient import errors
import subprocess
#256MB Overhead - Adjust as needed.
DOWNLOAD_CHUNK_SZ = (1024*1024*256)

def get_game_list(dsvc):
	ftbl = {}
	games = {}
	ftbl = get_game_fids(dsvc)
	games = get_meta(dsvc,ftbl)
	return games
def get_meta(service,ftbl):
	games = {}
	for f in ftbl:
		
		for g in f.keys():
			properties = {}
			for p in f["properties"]:
				properties[p["key"]] = p["value"]
			games[f["id"]] = {"filename":f['title'],"f_sz":int(f["fileSize"]),"download_url":f["downloadUrl"],"game_name":properties["game_name"],"game_publisher":properties["game_publisher"],"game_developer":properties["game_developer"],"game_region":properties["game_region"],"game_emu_status":properties["game_emu_status"],"game_year":properties["game_year"],"game_players":properties["game_players"],"game_preview_video":properties["game_preview_video"],"game_cover_front":properties["game_cover_front"],"game_cover_back":properties["game_cover_back"],"game_media":properties["game_media"],"game_content_rating":properties["game_content_rating"]}
			
	return games
	
def get_game_fids(service):
	result = []
	page_token = None
	while True:
		try:
			param = {}
			#Only get EmuCloud  PS2 Files.
			param['q'] = "properties has { key='media_key' and value='EmuCloud' and visibility='PRIVATE'} and properties has { key='game_emu' and value='PCSX2' and visibility='PRIVATE'} "
			if page_token:
				param['pageToken'] = page_token
			files = service.files().list(**param).execute()
			result.extend(files['items'])
			page_token = files.get('nextPageToken')
			if not page_token:
				break
		except errors.HttpError, error:
			print 'An error occurred: %s' % error
			break
	return result
	
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
	
def download_game(service,gid,game,f0=0):
	print("Downloading Game...")
	f_offset = f0
	chk_sz = DOWNLOAD_CHUNK_SZ
	f = open(os.path.join('ps2tmp',game["filename"]), 'wb')
	while(f_offset < game['f_sz']):
		if(f_offset > (game['f_sz'] - DOWNLOAD_CHUNK_SZ)):
			chk_sz = game['f_sz'] - DOWNLOAD_CHUNK_SZ
		else:
			chk_sz = DOWNLOAD_CHUNK_SZ
		if(game['f_sz'] < DOWNLOAD_CHUNK_SZ):
			resp, content = service._http.request(game['download_url']) 
			if resp.status != 200 and resp.status != 206:
				print("Download Error - Retrying...")
				print(resp.status)
				f.close() 
				download_game(service,gid,game,f_offset)
			else:
				f.write(content)
				f.close()
				return
		else:
			resp, content = service._http.request(game['download_url'], headers={'Range': 'bytes=%d-%d' % (f_offset,f_offset+chk_sz)}) 
			if resp.status != 200 and resp.status != 206:
				print("Download Error - Retrying...")
				print(resp.status)
				f.close() 
				download_game(service,gid,game,f_offset)
		f.write(content)
		#FUCKING OFF BY ONE!
		f_offset += chk_sz+1
		
		if(f_offset > game['f_sz']):
			f_offset = game['f_sz']
		print("Progress: %.2f%%(%d/%d)\r" % ((float(f_offset)/float(game['f_sz'])*100,f_offset/(1024*1024),game['f_sz']/(1024*1024))))
		
				
	f.close() 

def play_game(game):
	subprocess.call(["pcsx2.exe",os.path.join("ps2tmp",game["filename"])])
	os.remove(os.path.join("ps2tmp",game["filename"]))
def game_select_menu(games):
	os.system("cls")
	print("PCSX2Cloud Ver 0.10")
	print("-------------------")
	select_counter = 1
	select_table = [""]
	for g in sorted(games.keys()):
		select_table.append(g)
		print("%d. %s %dMB" % (select_counter,games[g]["game_name"],games[g]["f_sz"] / (1024*1024)))
		select_counter+=1
	result = None
	try:
		result = games[select_table[int(raw_input("Select Game: "))]]
	except:
		result = None
	return g,result
	
	
if(__name__=="__main__"):
	if(not os.path.exists("ps2tmp")):
		os.makedirs("ps2tmp")
	else:
		shutil.rmtree("ps2tmp")
		os.makedirs("ps2tmp")
	#Drive Login
	dsvc = gc_auth.drive_login()

	while(True):
		games = get_game_list(dsvc)
		if(len(games) < 1):
			print("No Games :(")
			exit(1)
		#You'd think doing this each time would incur a lot of Overhead - it doesn't, actually
		gid,game = game_select_menu(games)
		if(game == None):
			continue
		download_game(dsvc,gid,game,0)
		play_game(game)
	