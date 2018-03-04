from .utils import make_metric_tree

METRIC_PREFIX = 'envoy.'

METRICS = {
    'runtime.load_error': {
        'tags': (),
        'method': 'count',
    },
    'runtime.override_dir_not_exists': {
        'tags': (),
        'method': 'count',
    },
    'runtime.override_dir_exists': {
        'tags': (),
        'method': 'count',
    },
    'runtime.load_success': {
        'tags': (),
        'method': 'count',
    },
    'runtime.num_keys': {
        'tags': (),
        'method': 'gauge',
    },
    'cluster_manager.cds.config_reload': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cds.update_attempt': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cds.update_success': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cds.update_failure': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cds.version': {
        'tags': (),
        'method': 'gauge',
    },
    'http.no_route': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.no_cluster': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.rq_redirect': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.rq_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'vhost.vcluster.upstream_rq_1xx': {
        'tags': ('virtual_host_name', 'virtual_cluster_name', ),
        'method': 'count',
    },
    'vhost.vcluster.upstream_rq_2xx': {
        'tags': ('virtual_host_name', 'virtual_cluster_name', ),
        'method': 'count',
    },
    'vhost.vcluster.upstream_rq_3xx': {
        'tags': ('virtual_host_name', 'virtual_cluster_name', ),
        'method': 'count',
    },
    'vhost.vcluster.upstream_rq_4xx': {
        'tags': ('virtual_host_name', 'virtual_cluster_name', ),
        'method': 'count',
    },
    'vhost.vcluster.upstream_rq_5xx': {
        'tags': ('virtual_host_name', 'virtual_cluster_name', ),
        'method': 'count',
    },
    'vhost.vcluster.upstream_rq_time': {
        'tags': ('virtual_host_name', 'virtual_cluster_name', ),
        'method': 'histogram',
    },
    'cluster.ratelimit.ok': {
        'tags': ('route_target_cluster', ),
        'method': 'count',
    },
    'cluster.ratelimit.error': {
        'tags': ('route_target_cluster', ),
        'method': 'count',
    },
    'cluster.ratelimit.over_limit': {
        'tags': ('route_target_cluster', ),
        'method': 'count',
    },
    'http.ip_tagging.hit': {
        'tags': ('stat_prefix', 'tag_name', ),
        'method': 'count',
    },
    'http.ip_tagging.no_hit': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.ip_tagging.total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'cluster.grpc.success': {
        'tags': ('route_target_cluster', 'grpc_service', 'grpc_method', ),
        'method': 'count',
    },
    'cluster.grpc.failure': {
        'tags': ('route_target_cluster', 'grpc_service', 'grpc_method', ),
        'method': 'count',
    },
    'cluster.grpc.total': {
        'tags': ('route_target_cluster', 'grpc_service', 'grpc_method', ),
        'method': 'count',
    },
    'http.dynamodb.operation.upstream_rq_total': {
        'tags': ('stat_prefix', 'operation_name', ),
        'method': 'count',
    },
    'http.dynamodb.operation.upstream_rq_time': {
        'tags': ('stat_prefix', 'operation_name', ),
        'method': 'histogram',
    },
    'http.dynamodb.table.upstream_rq_total': {
        'tags': ('stat_prefix', 'table_name', ),
        'method': 'count',
    },
    'http.dynamodb.table.upstream_rq_time': {
        'tags': ('stat_prefix', 'table_name', ),
        'method': 'histogram',
    },
    'http.dynamodb.error': {
        'tags': ('stat_prefix', 'table_name', 'error_type', ),
        'method': 'count',
    },
    'http.dynamodb.error.BatchFailureUnprocessedKeys': {
        'tags': ('stat_prefix', 'table_name', ),
        'method': 'count',
    },
    'http.buffer.rq_timeout': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.rds.config_reload': {
        'tags': ('stat_prefix', 'route_config_name', ),
        'method': 'count',
    },
    'http.rds.update_attempt': {
        'tags': ('stat_prefix', 'route_config_name', ),
        'method': 'count',
    },
    'http.rds.update_success': {
        'tags': ('stat_prefix', 'route_config_name', ),
        'method': 'count',
    },
    'http.rds.update_failure': {
        'tags': ('stat_prefix', 'route_config_name', ),
        'method': 'count',
    },
    'http.rds.version': {
        'tags': ('stat_prefix', 'route_config_name', ),
        'method': 'gauge',
    },
    'tcp.downstream_cx_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'tcp.downstream_cx_no_route': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'tcp.downstream_cx_tx_bytes_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'tcp.downstream_cx_tx_bytes_buffered': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'tcp.downstream_flow_control_paused_reading_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'tcp.downstream_flow_control_resumed_reading_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.update_success': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.update_failure': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.auth_no_ssl': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.auth_ip_white_list': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.auth_digest_match': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.auth_digest_no_match': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'auth.clientssl.total_principals': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'ratelimit.total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'ratelimit.error': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'ratelimit.over_limit': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'ratelimit.ok': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'ratelimit.cx_closed': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'ratelimit.active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'redis.downstream_cx_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'redis.downstream_cx_protocol_error': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.downstream_cx_rx_bytes_buffered': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'redis.downstream_cx_rx_bytes_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.downstream_cx_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.downstream_cx_tx_bytes_buffered': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'redis.downstream_cx_tx_bytes_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.downstream_cx_drain_close': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.downstream_rq_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'redis.downstream_rq_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.splitter.invalid_request': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.splitter.unsupported_command': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'redis.command.total': {
        'tags': ('stat_prefix', 'command', ),
        'method': 'count',
    },
    'mongo.decoding_error': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.delay_injected': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_get_more': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_insert': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_kill_cursors': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_tailable_cursor': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_no_cursor_timeout': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_await_data': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_exhaust': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_no_max_time': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_scatter_get': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_multi_get': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_query_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'mongo.op_reply': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_reply_cursor_not_found': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_reply_query_failure': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.op_reply_valid_cursor': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.cx_destroy_local_with_active_rq': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.cx_destroy_remote_with_active_rq': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.cx_drain_close': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'mongo.cmd.total': {
        'tags': ('stat_prefix', 'cmd', ),
        'method': 'count',
    },
    'mongo.cmd.reply_num_docs': {
        'tags': ('stat_prefix', 'cmd', ),
        'method': 'histogram',
    },
    'mongo.cmd.reply_size': {
        'tags': ('stat_prefix', 'cmd', ),
        'method': 'histogram',
    },
    'mongo.cmd.reply_time_ms': {
        'tags': ('stat_prefix', 'cmd', ),
        'method': 'histogram',
    },
    'mongo.collection.query.total': {
        'tags': ('stat_prefix', 'collection', ),
        'method': 'count',
    },
    'mongo.collection.query.scatter_get': {
        'tags': ('stat_prefix', 'collection', ),
        'method': 'count',
    },
    'mongo.collection.query.multi_get': {
        'tags': ('stat_prefix', 'collection', ),
        'method': 'count',
    },
    'mongo.collection.query.reply_num_docs': {
        'tags': ('stat_prefix', 'collection', ),
        'method': 'histogram',
    },
    'mongo.collection.query.reply_size': {
        'tags': ('stat_prefix', 'collection', ),
        'method': 'histogram',
    },
    'mongo.collection.query.reply_time_ms': {
        'tags': ('stat_prefix', 'collection', ),
        'method': 'histogram',
    },
    'mongo.collection.callsite.query.total': {
        'tags': ('stat_prefix', 'collection', 'callsite', ),
        'method': 'count',
    },
    'mongo.collection.callsite.query.scatter_get': {
        'tags': ('stat_prefix', 'collection', 'callsite', ),
        'method': 'count',
    },
    'mongo.collection.callsite.query.multi_get': {
        'tags': ('stat_prefix', 'collection', 'callsite', ),
        'method': 'count',
    },
    'mongo.collection.callsite.query.reply_num_docs': {
        'tags': ('stat_prefix', 'collection', 'callsite', ),
        'method': 'histogram',
    },
    'mongo.collection.callsite.query.reply_size': {
        'tags': ('stat_prefix', 'collection', 'callsite', ),
        'method': 'histogram',
    },
    'mongo.collection.callsite.query.reply_time_ms': {
        'tags': ('stat_prefix', 'collection', 'callsite', ),
        'method': 'histogram',
    },
    'listener.downstream_cx_total': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.downstream_cx_destroy': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.downstream_cx_active': {
        'tags': ('address', ),
        'method': 'gauge',
    },
    'listener.downstream_cx_length_ms': {
        'tags': ('address', ),
        'method': 'histogram',
    },
    'listener.ssl.connection_error': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.handshake': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.session_reused': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.no_certificate': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.fail_no_sni_match': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.fail_verify_no_cert': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.fail_verify_error': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.fail_verify_san': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.fail_verify_cert_hash': {
        'tags': ('address', ),
        'method': 'count',
    },
    'listener.ssl.cipher': {
        'tags': ('address', 'cipher', ),
        'method': 'count',
    },
    'listener_manager.listener_added': {
        'tags': (),
        'method': 'count',
    },
    'listener_manager.listener_modified': {
        'tags': (),
        'method': 'count',
    },
    'listener_manager.listener_removed': {
        'tags': (),
        'method': 'count',
    },
    'listener_manager.listener_create_success': {
        'tags': (),
        'method': 'count',
    },
    'listener_manager.listener_create_failure': {
        'tags': (),
        'method': 'count',
    },
    'listener_manager.total_listeners_warming': {
        'tags': (),
        'method': 'gauge',
    },
    'listener_manager.total_listeners_active': {
        'tags': (),
        'method': 'gauge',
    },
    'listener_manager.total_listeners_draining': {
        'tags': (),
        'method': 'gauge',
    },
    'http.downstream_cx_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_ssl_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_http1_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_websocket_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_http2_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_destroy': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_destroy_remote': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_destroy_local': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_destroy_active_rq': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_destroy_local_active_rq': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_destroy_remote_active_rq': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_ssl_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_http1_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_websocket_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_http2_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_protocol_error': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_length_ms': {
        'tags': ('stat_prefix', ),
        'method': 'histogram',
    },
    'http.downstream_cx_rx_bytes_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_rx_bytes_buffered': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_tx_bytes_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_tx_bytes_buffered': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_cx_drain_close': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_cx_idle_timeout': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_flow_control_paused_reading_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_flow_control_resumed_reading_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_http1_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_http2_total': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_active': {
        'tags': ('stat_prefix', ),
        'method': 'gauge',
    },
    'http.downstream_rq_response_before_rq_complete': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_rx_reset': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_tx_reset': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_non_relative_path': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_too_large': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_1xx': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_2xx': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_3xx': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_4xx': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_5xx': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_ws_on_non_ws_route': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.downstream_rq_time': {
        'tags': ('stat_prefix', ),
        'method': 'histogram',
    },
    'http.rs_too_large': {
        'tags': ('stat_prefix', ),
        'method': 'count',
    },
    'http.user_agent.downstream_cx_total': {
        'tags': ('stat_prefix', 'user_agent', ),
        'method': 'count',
    },
    'http.user_agent.downstream_cx_destroy_remote_active_rq': {
        'tags': ('stat_prefix', 'user_agent', ),
        'method': 'count',
    },
    'http.user_agent.downstream_rq_total': {
        'tags': ('stat_prefix', 'user_agent', ),
        'method': 'count',
    },
    'listener.http.downstream_rq_1xx': {
        'tags': ('address', 'stat_prefix', ),
        'method': 'count',
    },
    'listener.http.downstream_rq_2xx': {
        'tags': ('address', 'stat_prefix', ),
        'method': 'count',
    },
    'listener.http.downstream_rq_3xx': {
        'tags': ('address', 'stat_prefix', ),
        'method': 'count',
    },
    'listener.http.downstream_rq_4xx': {
        'tags': ('address', 'stat_prefix', ),
        'method': 'count',
    },
    'listener.http.downstream_rq_5xx': {
        'tags': ('address', 'stat_prefix', ),
        'method': 'count',
    },
    'http2.rx_reset': {
        'tags': (),
        'method': 'count',
    },
    'http2.tx_reset': {
        'tags': (),
        'method': 'count',
    },
    'http2.header_overflow': {
        'tags': (),
        'method': 'count',
    },
    'http2.trailers': {
        'tags': (),
        'method': 'count',
    },
    'http2.headers_cb_no_stream': {
        'tags': (),
        'method': 'count',
    },
    'http2.too_many_header_frames': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cluster_added': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cluster_modified': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.cluster_removed': {
        'tags': (),
        'method': 'count',
    },
    'cluster_manager.total_clusters': {
        'tags': (),
        'method': 'gauge',
    },
    'cluster.upstream_cx_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_active': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.upstream_cx_http1_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_http2_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_connect_fail': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_connect_timeout': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_connect_attempts_exceeded': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_overflow': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_connect_ms': {
        'tags': ('name', ),
        'method': 'histogram',
    },
    'cluster.upstream_cx_length_ms': {
        'tags': ('name', ),
        'method': 'histogram',
    },
    'cluster.upstream_cx_destroy': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_destroy_local': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_destroy_remote': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_destroy_with_active_rq': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_destroy_local_with_active_rq': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_destroy_remote_with_active_rq': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_close_notify': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_rx_bytes_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_rx_bytes_buffered': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.upstream_cx_tx_bytes_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_tx_bytes_buffered': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.upstream_cx_protocol_error': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_max_requests': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_cx_none_healthy': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_active': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.upstream_rq_pending_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_pending_overflow': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_pending_failure_eject': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_pending_active': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.upstream_rq_cancelled': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_maintenance_mode': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_timeout': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_per_try_timeout': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_rx_reset': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_tx_reset': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_retry': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_retry_success': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_retry_overflow': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_flow_control_paused_reading_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_flow_control_resumed_reading_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_flow_control_backed_up_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_flow_control_drained_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.membership_change': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.membership_healthy': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.membership_total': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.retry_or_shadow_abandoned': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.config_reload': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.update_attempt': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.update_success': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.update_failure': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.version': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.max_host_weight': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.bind_errors': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.attempt': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.success': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.failure': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.passive_failure': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.network_failure': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.verify_cluster': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.health_check.healthy': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.outlier_detection.ejections_enforced_total': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_active': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.outlier_detection.ejections_overflow': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_enforced_consecutive_5xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_detected_consecutive_5xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_enforced_success_rate': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_detected_success_rate': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_enforced_consecutive_gateway_failure': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.outlier_detection.ejections_detected_consecutive_gateway_failure': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_1xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_2xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_3xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_4xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_5xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.upstream_rq_time': {
        'tags': ('name', ),
        'method': 'histogram',
    },
    'cluster.canary.upstream_rq_1xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.canary.upstream_rq_2xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.canary.upstream_rq_3xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.canary.upstream_rq_4xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.canary.upstream_rq_5xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.canary.upstream_rq_time': {
        'tags': ('name', ),
        'method': 'histogram',
    },
    'cluster.internal.upstream_rq_1xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.internal.upstream_rq_2xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.internal.upstream_rq_3xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.internal.upstream_rq_4xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.internal.upstream_rq_5xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.internal.upstream_rq_time': {
        'tags': ('name', ),
        'method': 'histogram',
    },
    'cluster.external.upstream_rq_1xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.external.upstream_rq_2xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.external.upstream_rq_3xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.external.upstream_rq_4xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.external.upstream_rq_5xx': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.external.upstream_rq_time': {
        'tags': ('name', ),
        'method': 'histogram',
    },
    'cluster.zone.upstream_rq_1xx': {
        'tags': ('name', 'from_zone', 'to_zone', ),
        'method': 'count',
    },
    'cluster.zone.upstream_rq_2xx': {
        'tags': ('name', 'from_zone', 'to_zone', ),
        'method': 'count',
    },
    'cluster.zone.upstream_rq_3xx': {
        'tags': ('name', 'from_zone', 'to_zone', ),
        'method': 'count',
    },
    'cluster.zone.upstream_rq_4xx': {
        'tags': ('name', 'from_zone', 'to_zone', ),
        'method': 'count',
    },
    'cluster.zone.upstream_rq_5xx': {
        'tags': ('name', 'from_zone', 'to_zone', ),
        'method': 'count',
    },
    'cluster.zone.upstream_rq_time': {
        'tags': ('name', 'from_zone', 'to_zone', ),
        'method': 'histogram',
    },
    'cluster.lb_healthy_panic': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_zone_cluster_too_small': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_zone_routing_all_directly': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_zone_routing_sampled': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_zone_routing_cross_zone': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_local_cluster_not_ok': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_zone_number_differs': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_subsets_active': {
        'tags': ('name', ),
        'method': 'gauge',
    },
    'cluster.lb_subsets_created': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_subsets_removed': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_subsets_selected': {
        'tags': ('name', ),
        'method': 'count',
    },
    'cluster.lb_subsets_fallback': {
        'tags': ('name', ),
        'method': 'count',
    },
}

METRIC_TREE = make_metric_tree(METRICS)
