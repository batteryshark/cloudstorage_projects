import sys,os


global PROVIDERS_DB
global IS_HALTED

API_INIT = False

MB = 1024*1024
GB = 1024*MB
TB = 1024*GB

def halt_process():
    global IS_HALTED
    IS_HALTED = True


def init():
    global API_INIT
    global IS_HALTED

    if(API_INIT == True):
        return
    IS_HALTED = False
    API_INIT = True
    # This DB of provider endpoints are keyed with a provider instance value. That value is passed to the provider
    # object to ensure we're communicating with the right provider instance.
    PROVIDERS_DB = {}


