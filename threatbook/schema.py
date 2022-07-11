DEFAULT_SCHEMA = {"response_code": "",
                  "verbose_msg": ""}

IP_QUERY_SCHEMA = {
    "samples": [],
    "tags_classes": [],
    "judgments": [
    ],
    "intelligences": {
        "threatbook_lab": [
            {
                "source": "",
                "confidence": "",
                "expired": "",
                "intel_tags": [],
                "find_time": "",
                "intel_types": [
                ],
                "update_time": ""
            },
            {
                "source": "",
                "confidence": "",
                "expired": "",
                "intel_tags": [],
                "find_time": "",
                "intel_types": [
                ],
                "update_time": ""
            }
        ],
        "x_reward": [],
        "open_source": []
    },
    "scene": "",
    "basic": {
        "carrier": "",
        "location": {
            "country": "",
            "province": "",
            "city": "",
            "lng": "",
            "lat": "",
            "country_code": ""
        }
    },
    "asn": {
        "rank": "",
        "info": "",
        "number": ""
    },
    "ports": [],
    "cas": [],
    "update_time": "",
    "rdns_list": [],
    "sum_cur_domains": ""
}

DOMAIN_QUERY_SCHEMA = {
    "judgments": [

    ],
    "rank": {
        "alexa_rank": {
            "global_rank": ""
        },
        "umbrella_rank": {
            "global_rank": ""
        }
    },
    "intelligences": {
        "threatbook_lab": [{
            "find_time": "",
            "expired": "",
            "confidence": "",
            "source": "",
            "intel_types": [

            ],
            "intel_tags": [{
                "tags_type": "",
                "tags": [

                ]
            },
                {
                    "tags_type": "",
                    "tags": []
                }
            ]
        }],
        "x_reward": [{
            "find_time": "",
            "expired": "",
            "confidence": "",
            "source": "",
            "intel_types": [

            ],
            "intel_tags": [{
                "tags_type": "",
                "tags": [

                ]
            },
                {
                    "tags_type": "",
                    "tags": [

                    ]
                }
            ]
        }],
        "open_source": [{
            "find_time": "",
            "expired": "",
            "confidence": "",
            "source": "",
            "intel_types": [

            ],
            "intel_tags": [{
                "tags_type": "",
                "tags": [

                ]
            },
                {
                    "tags_type": "",
                    "tags": [

                    ]
                }
            ]
        }]
    },
    "tags_classes": [{
        "tags_type": "",
        "tags": [

        ]
    },
        {
            "tags_type": "",
            "tags": [

            ]
        }
    ],
    "samples": [{
        "sha256": "",
        "scan_time": "",
        "malware_type": "",
        "ratio": "",
        "malware_family": ""
    }],
    "cur_ips": [{
        "ip": "",
        "carrier": "",
        "location": {
            "country": "",
            "country_code": "",
            "province": "",
            "lng": "",
            "city": "",
            "lat": ""
        }
    },
        {
            "ip": "",
            "carrier": "",
            "location": {
                "country": "",
                "country_code": "",
                "province": "",
                "lng": "",
                "city": "",
                "lat": ""
            }
        }
    ],
    "cur_whois": {
        "registrant_phone": "",
        "name_server": "",
        "cdate": "",
        "registrant_address": "",
        "registrar_name": "",
        "registrant_name": "",
        "alexa": "",
        "registrant_email": "",
        "registrant_company": "",
        "udate": "",
        "edate": ""
    },
    "categories": {
        "first_cats": [],
        "second_cats": ""
    },
    "cas": [{
        "subject": "",
        "issuer": "",
        "fingerprint": "",
        "purpose": "",
        "verify": "",
        "status": "",
        "revoked": "",
        "begin": "",
        "end": "",
        "status_desc": "",
        "serial_number": "",
        "revoked_time": ""
    }]
}

DOMAIN_NAME_CONTEXT_SCHEMA = {
    "context": [
        {
            "sample": "",
            "source_urls": []
        },
        {
            "sample": "",
            "source_urls": [
                {
                    "ip": "",
                    "url": ""
                }
            ]
        }
    ],
    "forensics": [
        {
            "sample": {
                "sha256": "",
                "tag": {
                    "s": [
                    ],
                    "x": [
                    ]
                },
                "domains": [
                    {
                        "domain": "",
                        "ip": ""
                    }
                ],
                "file_type": "",
                "malware_family": "",
                "malware_type": "",
                "threat_level": ""
            },
            "suggestion": {

            }
        }
    ]
}

