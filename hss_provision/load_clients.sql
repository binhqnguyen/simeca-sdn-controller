/* ---------001011234567890--------- */
insert into imsu set id=2, name='auto001011234567890', id_capabilities_set=1;

insert into imsi set id=2, id_imsu=2, identity='001011234567890',
            odb_barring=0, mme_address='', mme_realm='', sgsn_address='',
            sgsn_realm='', msc_address='', msc_realm='', apn_oi_replacement='',
            id_qos_profile_default=1, ics_indicator=1, network_access_mode=2,
            id_apn_configuration_profile=1, amf=0x8000,op='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', non_3gpp_status=0;

insert into imsi_allowed_apn set id_imsi=2, id_apn_configuration_profile=1,priority=10;

insert into imsi_apn set id_imsi=2, id_apn_configuration_profile=1,
            id_apn_configuration=4, ipv4='', ipv6='',
            pgw_identity='pgw.epc.mnc001.mcc001.3gppnetwork.org',
            pgw_realm='epc.mnc001.mcc001.3gppnetwork.org',
            pgw_ipv4='192.168.1.10', pgw_ipv6='fc00:1234:1::10', is_static_pgw=1;

insert into imsi_visited_network set id_imsi=2, id_visited_network=1;

/* ---------001011234567891--------- */
insert into imsu set id=3, name='auto001011234567891', id_capabilities_set=1;

insert into imsi set id=3, id_imsu=3, identity='001011234567891',
            odb_barring=0, mme_address='', mme_realm='', sgsn_address='',
            sgsn_realm='', msc_address='', msc_realm='', apn_oi_replacement='',
            id_qos_profile_default=1, ics_indicator=1, network_access_mode=2,
            id_apn_configuration_profile=1, amf=0x8000,op='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', non_3gpp_status=0;

insert into imsi_allowed_apn set id_imsi=3, id_apn_configuration_profile=1,priority=10;

insert into imsi_apn set id_imsi=3, id_apn_configuration_profile=1,
            id_apn_configuration=4, ipv4='', ipv6='',
            pgw_identity='pgw.epc.mnc001.mcc001.3gppnetwork.org',
            pgw_realm='epc.mnc001.mcc001.3gppnetwork.org',
            pgw_ipv4='192.168.1.10', pgw_ipv6='fc00:1234:1::10', is_static_pgw=1;

insert into imsi_visited_network set id_imsi=3, id_visited_network=1;

/* ---------001011234567892--------- */
insert into imsu set id=4, name='auto001011234567892', id_capabilities_set=1;

insert into imsi set id=4, id_imsu=4, identity='001011234567892',
            odb_barring=0, mme_address='', mme_realm='', sgsn_address='',
            sgsn_realm='', msc_address='', msc_realm='', apn_oi_replacement='',
            id_qos_profile_default=1, ics_indicator=1, network_access_mode=2,
            id_apn_configuration_profile=1, amf=0x8000,op='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', non_3gpp_status=0;

insert into imsi_allowed_apn set id_imsi=4, id_apn_configuration_profile=1,priority=10;

insert into imsi_apn set id_imsi=4, id_apn_configuration_profile=1,
            id_apn_configuration=4, ipv4='', ipv6='',
            pgw_identity='pgw.epc.mnc001.mcc001.3gppnetwork.org',
            pgw_realm='epc.mnc001.mcc001.3gppnetwork.org',
            pgw_ipv4='192.168.1.10', pgw_ipv6='fc00:1234:1::10', is_static_pgw=1;

insert into imsi_visited_network set id_imsi=4, id_visited_network=1;

