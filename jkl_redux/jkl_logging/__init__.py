"""
     Generic Internal Logging functionality
"""

import sys, logging,logging.handlers
import jkl_globals

LOGLEVEL_DB = {
    "DEBUG" : logging.DEBUG,
    "INFO"  : logging.INFO,
    "WARN"  : logging.WARN,
    "ERROR" : logging.ERROR,
    "FATAL" : logging.FATAL,
}

class Log(object):
    def __init__(self,module_name,log_level="DEBUG"):
        self.name = module_name
        self.logger = logging.getLogger("%s_Logger" % self.name)
        self.log_level = None
        self.consoleHandler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(self.consoleHandler)

        # Set initial loglevel based on config.
        self.set_loglevel(log_level)


    # Set a new loglevel.
    def set_loglevel(self,log_level):
        self.log_level = log_level
        self.logger.setLevel(LOGLEVEL_DB[self.log_level])

    # Handling based on loglevels.
    def WARN(self,msg):
        self.logger.warn("%s : %s" % (self.name,msg))

    def FATAL(self,msg):
        self.logger.fatal("%s : %s" % (self.name,msg))
        jkl_globals.halt_process()

    def ERROR(self,msg):
        self.logger.error("%s : %s" % (self.name, msg))

    def INFO(self,msg):
        self.logger.info("%s : %s" % (self.name, msg))

    def DEBUG(self,msg):
        self.logger.debug("%s : %s" % (self.name,msg))
