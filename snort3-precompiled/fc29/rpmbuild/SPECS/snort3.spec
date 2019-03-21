Name:           snort3
Version:        0.1
Release:        1%{?dist}
Summary:        Snort 3 Beta precompiled binaries. 
License:        GPLv2

#BuildRequires:  autoconf

%description
Snort 3 Beta precompiled binaries. 

%prep

%build

%install
cp -r %{_builddir}/usr %{buildroot}

%files
/usr/bin/appid_detector_builder.sh
/usr/bin/u2boat
/usr/bin/snort
/usr/bin/u2spewfoo
/usr/bin/snort2lua
/usr/lib64/snort/daqs/daq_file.so
/usr/lib64/snort/daqs/daq_hext.so
/usr/lib64/pkgconfig/snort.pc
/usr/lib64/snort_extra/codecs/cd_wlan.so
/usr/lib64/snort_extra/codecs/cd_token_ring.so
/usr/lib64/snort_extra/codecs/cd_eapol.so
/usr/lib64/snort_extra/codecs/cd_ppp.so
/usr/lib64/snort_extra/codecs/cd_null.so
/usr/lib64/snort_extra/codecs/cd_slip.so
/usr/lib64/snort_extra/codecs/cd_pbb.so
/usr/lib64/snort_extra/codecs/cd_pflog.so
/usr/lib64/snort_extra/codecs/cd_linux_sll.so
/usr/lib64/snort_extra/loggers/alert_ex.so
/usr/lib64/snort_extra/loggers/log_null.so
/usr/lib64/snort_extra/loggers/alert.lua
/usr/lib64/snort_extra/daqs/daq_regtest.so
/usr/lib64/snort_extra/daqs/daq_socket.so
/usr/lib64/snort_extra/ips_options/ips_urg.so
/usr/lib64/snort_extra/ips_options/ips_mss.so
/usr/lib64/snort_extra/ips_options/ips_pkt_num.so
/usr/lib64/snort_extra/ips_options/find.lua
/usr/lib64/snort_extra/ips_options/ips_wscale.so
/usr/lib64/snort_extra/ips_options/ips_dns_tunnel.so
/usr/lib64/snort_extra/so_rules/sid_18758.so
/usr/lib64/snort_extra/inspectors/reg_test.so
/usr/lib64/snort_extra/inspectors/domain_filter.so
/usr/lib64/snort_extra/inspectors/dpx.so
/usr/lib64/snort_extra/inspectors/data_log.so
/usr/lib64/snort_extra/search_engines/lowmem.so
/usr/share/doc/snort/snort2lua.txt
/usr/share/doc/snort/telnet.txt
/usr/share/doc/snort/active.txt
/usr/share/doc/snort/byte_test.txt
/usr/share/doc/snort/high_availability.txt
/usr/share/doc/snort/plugins.txt
/usr/share/doc/snort/config.txt
/usr/share/doc/snort/commands.txt
/usr/share/doc/snort/building.txt
/usr/share/doc/snort/testing_numerical_values.txt
/usr/share/doc/snort/usage.txt
/usr/share/doc/snort/snort2lua_cmds.txt
/usr/share/doc/snort/enviro.txt
/usr/share/doc/snort/file_processing.txt
/usr/share/doc/snort/overview.txt
/usr/share/doc/snort/snort3x.png
/usr/share/doc/snort/snort_manual.text
/usr/share/doc/snort/snort2x.png
/usr/share/doc/snort/help.txt
/usr/share/doc/snort/byte_math.txt
/usr/share/doc/snort/tutorial.txt
/usr/share/doc/snort/codec.txt
/usr/share/doc/snort/perf_monitor.txt
/usr/share/doc/snort/wizard.txt
/usr/share/doc/snort/builtin.txt
/usr/share/doc/snort/ftp.txt
/usr/share/doc/snort/connector.txt
/usr/share/doc/snort/module_trace.txt
/usr/share/doc/snort/byte_extract.txt
/usr/share/doc/snort/extending.txt
/usr/share/doc/snort/port_scan.txt
/usr/share/doc/snort/features.txt
/usr/share/doc/snort/options.txt
/usr/share/doc/snort/pop_imap.txt
/usr/share/doc/snort/version.txt
/usr/share/doc/snort/logger.txt
/usr/share/doc/snort/data.txt
/usr/share/doc/snort/snort_manual.html
/usr/share/doc/snort/params.txt
/usr/share/doc/snort/concepts.txt
/usr/share/doc/snort/dcerpc.txt
/usr/share/doc/snort/basic.txt
/usr/share/doc/snort/reload_limitations.txt
/usr/share/doc/snort/binder.txt
/usr/share/doc/snort/daq.txt
/usr/share/doc/snort/http2_inspect.txt
/usr/share/doc/snort/snorty.png
/usr/share/doc/snort/config_changes.txt
/usr/share/doc/snort/reference.txt
/usr/share/doc/snort/counts.txt
/usr/share/doc/snort/gids.txt
/usr/share/doc/snort/terms.txt
/usr/share/doc/snort/differences.txt
/usr/share/doc/snort/snort_manual.txt
/usr/share/doc/snort/modules.txt
/usr/share/doc/snort/snort_manual.pdf
/usr/share/doc/snort/signals.txt
/usr/share/doc/snort/http_inspect.txt
/usr/share/doc/snort/connectors.txt
/usr/share/doc/snort/side_channel.txt
/usr/share/doc/snort/byte_jump.txt
/usr/share/doc/snort/ips_option.txt
/usr/share/doc/snort/appid.txt
/usr/share/doc/snort/README.u2boat
/usr/share/doc/snort/daq_readme.txt
/usr/share/doc/snort/ips_action.txt
/usr/share/doc/snort/smtp.txt
/usr/share/doc/snort/errors.txt
/usr/share/doc/snort/inspector.txt
/usr/share/doc/snort/sensitive_data.txt
/usr/share/doc/snort/style.txt
/usr/etc/snort/file_magic.lua
/usr/etc/snort/snort3-community.rules
/usr/etc/snort/snort-custom.lua
/usr/etc/snort/inline.lua
/usr/etc/snort/sid-msg.map
/usr/etc/snort/snort_defaults.lua
/usr/etc/snort/talos.lua
/usr/etc/snort/snort.lua
/usr/include/snort/codecs/codec_module.h
/usr/include/snort/lua/snort_config.lua
/usr/include/snort/lua/snort_plugin.lua
/usr/include/snort/managers/codec_manager.h
/usr/include/snort/managers/inspector_manager.h
/usr/include/snort/file_api/file_lib.h
/usr/include/snort/file_api/file_config.h
/usr/include/snort/file_api/file_identifier.h
/usr/include/snort/file_api/file_service.h
/usr/include/snort/file_api/file_flows.h
/usr/include/snort/file_api/file_module.h
/usr/include/snort/file_api/file_policy.h
/usr/include/snort/file_api/file_api.h
/usr/include/snort/file_api/file_segment.h
/usr/include/snort/actions/actions.h
/usr/include/snort/hash/lru_cache_shared.h
/usr/include/snort/hash/ghash.h
/usr/include/snort/hash/xhash.h
/usr/include/snort/hash/hashfcn.h
/usr/include/snort/hash/hashes.h
/usr/include/snort/profiler/rule_profiler_defs.h
/usr/include/snort/profiler/memory_defs.h
/usr/include/snort/profiler/profiler.h
/usr/include/snort/profiler/memory_profiler_defs.h
/usr/include/snort/profiler/time_profiler_defs.h
/usr/include/snort/profiler/profiler_defs.h
/usr/include/snort/profiler/memory_context.h
/usr/include/snort/framework/logger.h
/usr/include/snort/framework/range.h
/usr/include/snort/framework/endianness.h
/usr/include/snort/framework/mpse.h
/usr/include/snort/framework/data_bus.h
/usr/include/snort/framework/inspector.h
/usr/include/snort/framework/cursor.h
/usr/include/snort/framework/connector.h
/usr/include/snort/framework/ips_option.h
/usr/include/snort/framework/lua_api.h
/usr/include/snort/framework/base_api.h
/usr/include/snort/framework/parameter.h
/usr/include/snort/framework/so_rule.h
/usr/include/snort/framework/codec.h
/usr/include/snort/framework/bits.h
/usr/include/snort/framework/counts.h
/usr/include/snort/framework/value.h
/usr/include/snort/framework/ips_action.h
/usr/include/snort/framework/decode_data.h
/usr/include/snort/framework/api_options.h
/usr/include/snort/framework/module.h
/usr/include/snort/framework/mpse_batch.h
/usr/include/snort/time/clock_defs.h
/usr/include/snort/time/tsc_clock.h
/usr/include/snort/time/packet_time.h
/usr/include/snort/time/stopwatch.h
/usr/include/snort/main/snort_types.h
/usr/include/snort/main/snort_config.h
/usr/include/snort/main/snort_debug.h
/usr/include/snort/main/thread.h
/usr/include/snort/main/analyzer_command.h
/usr/include/snort/main/policy.h
/usr/include/snort/daqs/daq_user.h
/usr/include/snort/decompress/file_decomp.h
/usr/include/snort/packet_io/active.h
/usr/include/snort/packet_io/sfdaq.h
/usr/include/snort/detection/detection_engine.h
/usr/include/snort/detection/regex_offload.h
/usr/include/snort/detection/ips_context_chain.h
/usr/include/snort/detection/rule_option_types.h
/usr/include/snort/detection/rules.h
/usr/include/snort/detection/detect_trace.h
/usr/include/snort/detection/detect.h
/usr/include/snort/detection/detection_options.h
/usr/include/snort/detection/treenodes.h
/usr/include/snort/detection/ips_context.h
/usr/include/snort/detection/ips_context_data.h
/usr/include/snort/detection/detection_util.h
/usr/include/snort/detection/signature.h
/usr/include/snort/sfip/sf_returns.h
/usr/include/snort/sfip/sf_ip.h
/usr/include/snort/sfip/sf_cidr.h
/usr/include/snort/protocols/layer.h
/usr/include/snort/protocols/token_ring.h
/usr/include/snort/protocols/packet.h
/usr/include/snort/protocols/vlan.h
/usr/include/snort/protocols/teredo.h
/usr/include/snort/protocols/udp.h
/usr/include/snort/protocols/arp.h
/usr/include/snort/protocols/mpls.h
/usr/include/snort/protocols/linux_sll.h
/usr/include/snort/protocols/protocol_ids.h
/usr/include/snort/protocols/packet_manager.h
/usr/include/snort/protocols/ip.h
/usr/include/snort/protocols/ipv6.h
/usr/include/snort/protocols/tcp_options.h
/usr/include/snort/protocols/ssl.h
/usr/include/snort/protocols/ipv4.h
/usr/include/snort/protocols/wlan.h
/usr/include/snort/protocols/tcp.h
/usr/include/snort/protocols/gre.h
/usr/include/snort/protocols/icmp4.h
/usr/include/snort/protocols/eth.h
/usr/include/snort/protocols/eapol.h
/usr/include/snort/protocols/icmp6.h
/usr/include/snort/protocols/ipv4_options.h
/usr/include/snort/events/event_queue.h
/usr/include/snort/events/event.h
/usr/include/snort/target_based/snort_protocols.h
/usr/include/snort/utils/sflsq.h
/usr/include/snort/utils/cpp_macros.h
/usr/include/snort/utils/bitop.h
/usr/include/snort/utils/endian.h
/usr/include/snort/utils/util_cstring.h
/usr/include/snort/utils/stats.h
/usr/include/snort/utils/kmap.h
/usr/include/snort/utils/safec.h
/usr/include/snort/utils/primed_allocator.h
/usr/include/snort/utils/util_unfold.h
/usr/include/snort/utils/util_utf.h
/usr/include/snort/utils/util_jsnorm.h
/usr/include/snort/utils/segment_mem.h
/usr/include/snort/utils/util.h
/usr/include/snort/utils/sfmemcap.h
/usr/include/snort/log/log_text.h
/usr/include/snort/log/u2_packet.h
/usr/include/snort/log/unified2.h
/usr/include/snort/log/messages.h
/usr/include/snort/log/obfuscator.h
/usr/include/snort/log/log.h
/usr/include/snort/log/text_log.h
/usr/include/snort/search_engines/search_tool.h
/usr/include/snort/search_engines/search_common.h
/usr/include/snort/flow/flow_key.h
/usr/include/snort/flow/flow.h
/usr/include/snort/flow/expect_cache.h
/usr/include/snort/network_inspectors/packet_tracer/packet_tracer.h
/usr/include/snort/network_inspectors/appid/appid_types.h
/usr/include/snort/network_inspectors/appid/appid_session_api.h
/usr/include/snort/network_inspectors/appid/appid_http_session.h
/usr/include/snort/network_inspectors/appid/appid_api.h
/usr/include/snort/network_inspectors/appid/http_xff_fields.h
/usr/include/snort/network_inspectors/appid/appid_dns_session.h
/usr/include/snort/network_inspectors/appid/application_ids.h
/usr/include/snort/mime/file_mime_log.h
/usr/include/snort/mime/file_mime_paf.h
/usr/include/snort/mime/file_mime_process.h
/usr/include/snort/mime/file_mime_config.h
/usr/include/snort/mime/file_mime_decode.h
/usr/include/snort/mime/decode_base.h
/usr/include/snort/mime/file_mime_context_data.h
/usr/include/snort/mime/decode_b64.h
/usr/include/snort/pub_sub/sip_events.h
/usr/include/snort/pub_sub/http_events.h
/usr/include/snort/pub_sub/expect_events.h
/usr/include/snort/pub_sub/appid_events.h
/usr/include/snort/helpers/base64_encoder.h
/usr/include/snort/stream/stream_splitter.h
/usr/include/snort/stream/paf.h
/usr/include/snort/stream/stream.h

