# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import requests

from datadog_checks.checks import AgentCheck

from .errors import UnknownMetric
from .parser import parse_metric


class Envoy(AgentCheck):
    SERVICE_CHECK_NAME = 'envoy.can_connect'

    def check(self, instance):
        stats_url = instance['stats_url']
        custom_tags = instance.get('tags', [])
        username = instance.get('username', None)
        password = instance.get('password', None)
        auth = (username, password) if username and password else None
        verify_ssl = not instance.get('disable_ssl_validation', False)
        proxies = self.get_instance_proxy(instance, stats_url)
        timeout = int(instance.get('timeout', 20))

        try:
            request = requests.get(
                stats_url, auth=auth, verify=verify_ssl, proxies=proxies, timeout=timeout
            )
        except requests.exceptions.Timeout:
            msg = 'Envoy endpoint `{}` timed out after {} seconds'.format(stats_url, timeout)
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL, message=msg)
            self.log.exception(msg)
            return
        except requests.exceptions.RequestException:
            msg = 'Error accessing Envoy endpoint `{}`'.format(stats_url)
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL, message=msg)
            self.log.exception(msg)
            return

        if request.status_code != 200:
            msg = 'Envoy endpoint `{}` responded with HTTP status code {}'.format(stats_url, request.status_code)
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL, message=msg)
            self.log.warning(msg)
            return

        get_method = getattr
        for line in request.content.decode().splitlines():
            try:
                envoy_metric, value = line.split(': ')
            except ValueError:
                continue

            value = int(value)

            try:
                metric, tags, method = parse_metric(envoy_metric)
            except UnknownMetric:
                self.log.debug('Unknown metric `{}`'.format(envoy_metric))
                continue

            tags.extend(custom_tags)
            get_method(self, method)(metric, value, tags=tags)

        self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.OK)
