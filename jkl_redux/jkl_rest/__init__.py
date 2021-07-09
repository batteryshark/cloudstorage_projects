# REST-Based Operations for Everything.
import jkl_globals,jkl_logging
import requests,time

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NO_CONTENT = 204
HTTP_NOTFOUND = 404
MAX_ATTEMPTS = 10
BACKOFF_MULT = 10

API_LIMIT = 10
API_CURRENT = 0
RATE_LIMIT = 0
RATE_LIMIT_LIMIT = 2

def do_get(url,params=None,data=None,headers=None):
    global API_LIMIT
    global API_CURRENT
    time.sleep(0.5)
    while(API_CURRENT >= API_LIMIT):
        time.sleep(1)
    API_CURRENT+=1
    params['acknowledgeAbuse'] = True

    response = requests.get(url,params=params,data=data,headers=headers)
    API_CURRENT -= 1
    return response

def do_post(url,params=None,data=None,json=None,headers=None):
    global API_LIMIT
    global API_CURRENT
    global RATE_LIMIT
    global RATE_LIMIT_LIMIT
    time.sleep(0.5)
    while(API_CURRENT >= API_LIMIT):
        time.sleep(1)
    API_CURRENT+=1
    result = None
    for i in range(0,MAX_ATTEMPTS):
        result = requests.post(url,params=params,json=json,data=data,headers=headers)
        if(result.status_code == HTTP_FORBIDDEN):
            print(url)
            print(headers)
            print(json)
            print(result.content)
            if("usageLimits" in result.content):
                RATE_LIMIT+=1
                if(RATE_LIMIT >= RATE_LIMIT_LIMIT):
                    time.sleep(1800)
                    RATE_LIMIT = 0
                    continue
                else:
                    time.sleep(500)
                    continue
            continue
        if(result.status_code == HTTP_OK):
            break
    API_CURRENT -=1
    return result

def do_patch(url,params=None,data=None,json=None,headers=None):
    global API_LIMIT
    global API_CURRENT
    time.sleep(0.5)
    while(API_CURRENT >= API_LIMIT):
        time.sleep(1)
    API_CURRENT+=1

    response = requests.post(url,params=params,json=json,data=data,headers=headers)
    API_CURRENT -=1
    return response

def do_put(url,params=None,data=None,json=None,headers=None):
    global API_LIMIT
    global API_CURRENT
    time.sleep(0.5)
    while(API_CURRENT >= API_LIMIT):
        time.sleep(1)
    API_CURRENT +=1
    response = requests.post(url,params=params,json=json,data=data,headers=headers)
    API_CURRENT -=1
    return response

def do_delete(url,params=None,data=None,json=None,headers=None):
    global API_LIMIT
    global API_CURRENT
    time.sleep(0.20)
    while(API_CURRENT >= API_LIMIT):
        time.sleep(1)
    API_CURRENT +=1
    response = requests.delete(url,params=params,data=data,json=json,headers=headers)
    API_CURRENT -=1
    return response