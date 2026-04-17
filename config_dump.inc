void write_string_array(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const std::vector<std::string>& values)
{
    writer.StartArray();
    for (const auto& value : values)
    {
        writer.String(value.c_str());
    }
    writer.EndArray();
}

void write_log(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::log_t& value)
{
    writer.Key("level");
    writer.String(value.level.c_str());
    writer.Key("file");
    writer.String(value.file.c_str());
}

void write_timeout(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::timeout_t& value)
{
    writer.Key("read");
    writer.Uint(value.read);
    writer.Key("write");
    writer.Uint(value.write);
    writer.Key("connect");
    writer.Uint(value.connect);
    writer.Key("idle");
    writer.Uint(value.idle);
}

void write_web_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::web_t& value)
{
    writer.Key("enabled");
    writer.Bool(value.enabled);
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
}

void write_socks_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::socks_t& value)
{
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
    writer.Key("auth");
    writer.Bool(value.auth);
    if (value.auth)
    {
        writer.Key("username");
        writer.String(value.username.c_str());
        writer.Key("password");
        writer.String(value.password.c_str());
    }
}

void write_tproxy_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::tproxy_t& value)
{
    writer.Key("listen_host");
    writer.String(value.listen_host.c_str());
    writer.Key("tcp_port");
    writer.Uint(value.tcp_port);
    writer.Key("udp_port");
    writer.Uint(value.udp_port);
    writer.Key("mark");
    writer.Uint(value.mark);
}

void write_tun_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::tun_t& value)
{
    writer.Key("name");
    writer.String(value.name.c_str());
    writer.Key("mtu");
    writer.Uint(value.mtu);
    writer.Key("ipv4");
    writer.String(value.ipv4.c_str());
    writer.Key("ipv4_prefix");
    writer.Uint(value.ipv4_prefix);
    writer.Key("ipv6");
    writer.String(value.ipv6.c_str());
    writer.Key("ipv6_prefix");
    writer.Uint(value.ipv6_prefix);
}

void write_reality_inbound_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::reality_inbound_t& value)
{
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
    writer.Key("sni");
    writer.String(value.sni.c_str());
    writer.Key("site_port");
    writer.Uint(value.site_port);
    writer.Key("private_key");
    writer.String(value.private_key.c_str());
    if (!value.public_key.empty())
    {
        writer.Key("public_key");
        writer.String(value.public_key.c_str());
    }
    writer.Key("short_id");
    writer.String(value.short_id.c_str());
    writer.Key("replay_cache_max_entries");
    writer.Uint(value.replay_cache_max_entries);
}

void write_reality_outbound_settings(rapidjson::PrettyWriter<rapidjson::StringBuffer>& writer, const config::reality_outbound_t& value)
{
    writer.Key("host");
    writer.String(value.host.c_str());
    writer.Key("port");
    writer.Uint(value.port);
    writer.Key("sni");
    writer.String(value.sni.c_str());
    writer.Key("fingerprint");
    writer.String(value.fingerprint.c_str());
    writer.Key("public_key");
    writer.String(value.public_key.c_str());
    writer.Key("short_id");
    writer.String(value.short_id.c_str());
    writer.Key("max_handshake_records");
    writer.Uint(value.max_handshake_records);
}
