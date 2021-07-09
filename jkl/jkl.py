# -*- encoding: utf-8 -*-
'''
    CloudStorage Substrate for OAuth2 Cloud Storage Services
'''

import os,sys,uuid,platform
from importlib import import_module
from ConfigParser import SafeConfigParser

class CloudStorage(object):
    def __init__(self,client_info_file):

        #In case we want to alert a remote machine to our driver's activity.
        self.client_machine = platform.node()
        self.user_cookie    = uuid.uuid4()

        #Load Client Configuration
        self.client_config = SafeConfigParser()
        self.client_info_file = client_info_file
        self.client_config.read(self.client_info_file)
        self.service_type  =  self.client_config.get('provider','service_type')
        
        #Pull API-Specific Functionality
        provider_path = 'providers.%s' % self.service_type.lower()
        self.ops = import_module(provider_path)
        self.root_dir = os.path.join(os.getcwd(), os.path.dirname(sys.argv[0]))
        
        #Initialize Provider
        self.ops.init(self)
