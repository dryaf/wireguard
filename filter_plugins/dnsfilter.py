"""Policy changes preserve unrelated DNS settings and validate flag types."""

ADS_RESOLVER = {
    "name": "adguard",
    "addr": "94.140.14.14:443",
    "url": "https://dns.adguard-dns.com/dns-query",
}
CATEGORIES = ("ads", "porn", "malware")


def validate_policy(config):
    if not isinstance(config, dict):
        raise ValueError("DNS filter configuration must be a mapping")
    for category in CATEGORIES:
        if type(config.get("filter_" + category, False)) is not bool:
            raise ValueError(f"filter_{category} must be a YAML boolean")
    return config


def update_policy(config, category, enabled):
    validate_policy(config)
    if category not in CATEGORIES or type(enabled) is not bool:
        raise ValueError("Choose ads, porn or malware and a boolean value")
    # Only top-level entries change. Deep-copying Ansible's lazy mapping also
    # copies its templating engine and reconstructs deprecated plugin loaders.
    # Keep nested values and their Ansible data tags intact.
    candidate = dict(config)
    candidate["filter_" + category] = enabled
    if candidate.get("filter_ads", False):
        candidate.setdefault("resolver_anti_ads", dict(ADS_RESOLVER))
    return candidate


class FilterModule:
    def filters(self):
        return {"dnsfilter_validate_policy": validate_policy, "dnsfilter_update_policy": update_policy}
