import re

#List of commands to run
commands={
    "sap" : {
        "command" : "show service sap-using | match Nu",
        "regex" : re.compile("Number of SAPs : (\d*)", re.MULTILINE),
        "default": '0'
    },
    "sdp" : {
        "command" : "show service sdp | match Nu",
        "regex" : re.compile("Number of SDPs : (\d*)", re.MULTILINE),
        "default": '0'
    },
    "sdp-using" : {
        "command" : "show service sdp-using | match Nu",
        "regex" : re.compile("Number of SDPs : (\d*)", re.MULTILINE),
        "default": '0'
    }
}