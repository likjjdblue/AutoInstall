#!/usr/bin/env python

class ESScript:
    DictA={
  "fulltext": {
    "_all": {
      "analyzer": "ik_max_word",
      "search_analyzer": "ik_max_word",
      "term_vector": "no",
      "store": "false"
    },
    "properties": {
      "content": {
        "type": "text",
        "analyzer": "ik_max_word",
        "search_analyzer": "ik_max_word",
        "copy_to": "true",
        "boost": 8
      }
    }
  }
}



    DictB={
    "logs":{
        "properties":{
            "classInfo":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "errorType":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "logDesc":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "logLevel":{
                "type":"keyword",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                }
            },
            "logResult":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "logTime":{
                "type":"keyword"
            },
            "logUser":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "logUserGroup":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "logUserIP":{
                "type":"keyword"
            },
            "machineIP":{
                "type":"text"
            },
            "module":{
                "type":"keyword"
            },
            "moduleName":{
                "type":"keyword"
            },
            "objName":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "operateType":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            },
            "siteId":{
                "type":"keyword"
            },
            "trueName":{
                "type":"text",
                "fields":{
                    "keyword":{
                        "type":"keyword",
                        "ignore_above":256
                    }
                },
                "analyzer":"ik_max_word",
                "fielddata":"true"
            }
        }
    }
}

   
