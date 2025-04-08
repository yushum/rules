# Shadowrocket & Mihomo Custom Rules

This repository provides a collection of carefully curated rule sets for [Shadowrocket](https://apps.apple.com/us/app/shadowrocket/id932747118) and [Mihomo](https://github.com/MetaCubeX/mihomo), primarily based on the excellent works of:

- [GMOogway/shadowrocket-rules](https://github.com/GMOogway/shadowrocket-rules)
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)

All rules are optimized for daily use, with a focus on simplicity, maintainability, and compatibility with real-world use cases.

## Usage (Shadowrocket)

To use the pre-configured Shadowrocket `.conf` file:

1. Open **Shadowrocket**, go to the **Config** tab.
2. Tap the **"+"** button at the top-right corner.
3. In the URL field, paste: `https://raw.githubusercontent.com/yushum/rules/master/conf/shadowrocket.conf`
4. Tap **Download**.

That's it — your configuration will be loaded automatically.

## Recommended MMDB Files (GeoIP)

To enable proper IP-based geo-routing (e.g., for `GeoIP`, `GeoIP-CN`, `GeoIP-ASN` rules), we recommend downloading and placing the following `.mmdb` files in your app or proxy configuration:

- **Country.mmdb** (GeoLite2 CN):  
[Download](https://github.com/Masaiki/GeoIP2-CN/raw/release/Country.mmdb)

- **ASN.mmdb** (GeoLite2 ASN):  
[Download](https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb)

> These files are updated regularly by their respective maintainers.

## License

This project is licensed under the [MIT License](./LICENSE).
