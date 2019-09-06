"""
See Issue #42

Version 1 could just collect metrics via the REST api:
- mapping_count
- mapping_ready_count
- mapping_rate gauge

"""

import time
import requests

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Summary, REGISTRY, Histogram


UPLOAD_REQUEST_LATENCY = Histogram('es_upload_request_latency_seconds', 'CLK upload request latency')

STATUS_REQUEST_LATENCY = Histogram('es_status_request_latency_seconds', 'Status Request Latency')
STATUS_REQUEST_COUNT = CounterMetricFamily('es_status_counter_total', 'Number of Status Requests')

MAPPING_RATE_GAUGE = GaugeMetricFamily('es_mapping_rate', 'Max number of comparisons per second')
MAPPING_COUNT = CounterMetricFamily('es_mapping_counter_total', 'Number of mappings')
READY_MAPPING_COUNT = CounterMetricFamily('es_mapping_counter_ready', 'Number of ready mappings')
