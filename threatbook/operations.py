""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
from os.path import join

import requests
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops
from integrations.crudhub import make_request
from requests import exceptions as req_exceptions

from .schema import *

logger = get_logger('threatbook')


class ThreatBook(object):
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, endpoint, params={}, payload={}, files=None, method='GET'):
        params.update({'apikey': self.api_key}) if not files else payload.update({'apikey': self.api_key})
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.debug("service_endpoint: {0}".format(service_endpoint))
        try:
            response = requests.request(method, service_endpoint, data=payload, params=params, files=files,
                                        verify=self.verify_ssl)
            if response.ok:
                json_data = json.loads(response.content.decode('utf-8'))
                response_code = json_data.get('response_code', 0)
                if response_code >= 0 and 'application/json' in response.headers.get('Content-Type', ''):
                    return json_data
                else:
                    raise ConnectorError(response.text)
            else:
                logger.error("Error: {0}".format(response.text))
                raise ConnectorError('Status Code: {0}, API Response: {1}'.format(response.status_code, response.text))
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(err)
            raise ConnectorError(str(err))


def remove_empty_params(params):
    query_params = {k: v for k, v in params.items() if v is not None and v != ''}
    return query_params


def get_str_to_list(param):
    if param and isinstance(param, str):
        param = param.split(',')
    elif param and isinstance(param, list):
        return param
    else:
        param = []
    params = [val.strip() for val in param if isinstance(param, list)]
    return params


def submit_ip(config, params):
    tb = ThreatBook(config)
    exclude_params = params.get('exclude')
    params['exclude'] = ','.join([elem.strip() for elem in exclude_params if exclude_params])
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/ip/query', params=query_params)


def get_ip_reputation(config, params):
    tb = ThreatBook(config)
    resource = get_str_to_list(params.get('resource'))
    params['resource'] = ','.join(resource)
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/scene/ip_reputation', params=query_params)


def domain_analysis(config, params):
    tb = ThreatBook(config)
    exclude_params = params.get('exclude')
    params['exclude'] = ','.join([elem.strip() for elem in exclude_params if exclude_params])
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/domain/query', params=query_params)


def loss_detection(config, params):
    tb = ThreatBook(config)
    resource = get_str_to_list(params.get('resource'))
    params['resource'] = ','.join(resource)
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/scene/dns', params=query_params)


def get_file_iri(params):
    value = str(params.get('value'))
    input_type = params.get('input')
    try:
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            return file_iri, file_name
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value, None
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def submit_file(config, params):
    tb = ThreatBook(config)
    file_iri, file_name = get_file_iri(params)
    params.pop('input', '')
    params.pop('value', '')
    file_details = download_file_from_cyops(file_iri)
    file_path = join('/tmp', file_details['cyops_file_path'])
    file_name = file_details['filename'] if not file_name else file_name
    query_params = remove_empty_params(params)
    files = {
        'file': (file_name, open(file_path, 'rb'))
    }
    return tb.make_rest_call('/v3/file/upload', payload=query_params, files=files, method='POST')


def get_file_reputation(config, params):
    tb = ThreatBook(config)
    hash_type = params.pop('hash_type', '').lower()
    params[hash_type] = params.pop('hash_value', '')
    params['query_fields'] = params.pop('query_fields', '').lower()
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/file/report', params=query_params)


def file_detection_report(config, params):
    tb = ThreatBook(config)
    hash_type = params.pop('hash_type', '').lower()
    params[hash_type] = params.pop('hash_value', '')
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/file/report/multiengines', params=query_params)


def scan_url(config, params):
    tb = ThreatBook(config)
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/url/scan', params=query_params)


def get_url_reputations(config, params):
    tb = ThreatBook(config)
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/url/report', params=query_params)


def run_ip_advance_query(config, params):
    tb = ThreatBook(config)
    exclude_params = params.get('exclude')
    params['exclude'] = ','.join([elem.strip() for elem in exclude_params if exclude_params])
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/ip/adv_query', params=query_params)


def run_domain_advance_query(config, params):
    tb = ThreatBook(config)
    exclude_params = params.get('exclude')
    params['exclude'] = ','.join([elem.strip() for elem in exclude_params if exclude_params])
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/domain/adv_query', params=query_params)


def run_sub_domain_query(config, params):
    tb = ThreatBook(config)
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/domain/sub_domains', params=query_params)


def get_domain_name_context(config, params):
    tb = ThreatBook(config)
    query_params = remove_empty_params(params)
    return tb.make_rest_call('/v3/scene/domain_context', params=query_params)


def get_output_schema(params, schema):
    field = params.get('resource')
    schema_template = DEFAULT_SCHEMA
    schema_template.update({"data": {field: schema}})
    return schema_template


def get_ip_analysis_schema(config, params):
    return get_output_schema(params, IP_QUERY_SCHEMA)


def get_domain_analysis_schema(config, params):
    return get_output_schema(params, DOMAIN_QUERY_SCHEMA)


def get_domain_name_context_schema(config, params):
    return get_output_schema(params, DOMAIN_NAME_CONTEXT_SCHEMA)


def _check_health(config):
    params = {'url': 'threatbook.cn'}
    return get_url_reputations(config, params)


operations = {
    'submit_ip': submit_ip,
    'domain_analysis': domain_analysis,
    'get_ip_reputation': get_ip_reputation,
    'loss_detection': loss_detection,
    'submit_file': submit_file,
    'get_file_reputation': get_file_reputation,
    'file_detection_report': file_detection_report,
    'scan_url': scan_url,
    'get_url_reputations': get_url_reputations,
    'run_ip_advance_query': run_ip_advance_query,
    'run_domain_advance_query': run_domain_advance_query,
    'run_sub_domain_query': run_sub_domain_query,
    'get_domain_name_context': get_domain_name_context,

    # below actions for handling dynamic output schema
    'get_ip_analysis_schema': get_ip_analysis_schema,
    'get_domain_analysis_schema': get_domain_analysis_schema,
    'get_domain_name_context_schema': get_domain_name_context_schema
}

