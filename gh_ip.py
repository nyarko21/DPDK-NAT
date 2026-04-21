import requests
import ipaddress

URL = "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest"

OUT_V4 = "afrinic-gh-ipv4-cidr.txt"
OUT_V6 = "afrinic-gh-ipv6-cidr.txt"


def ipv4_to_cidrs(start_ip, count):
    start = int(ipaddress.IPv4Address(start_ip))
    end = start + int(count)

    cidrs = []
    while start < end:
        max_size = start & -start  # lowest set bit
        remaining = end - start

        while max_size > remaining:
            max_size >>= 1

        prefix = 32 - (max_size.bit_length() - 1)
        cidrs.append(str(ipaddress.IPv4Address(start)) + f"/{prefix}")

        start += max_size

    return cidrs


def ipv6_to_cidrs(start_ip, count):
    start = int(ipaddress.IPv6Address(start_ip))
    end = start + int(count)

    cidrs = []
    while start < end:
        max_size = start & -start
        remaining = end - start

        while max_size > remaining:
            max_size >>= 1

        prefix = 128 - (max_size.bit_length() - 1)
        cidrs.append(str(ipaddress.IPv6Address(start)) + f"/{prefix}")

        start += max_size

    return cidrs


def main():
    print("Downloading AFRINIC data...")
    data = requests.get(URL, timeout=30).text.splitlines()

    with open(OUT_V4, "w") as f4, open(OUT_V6, "w") as f6:
        for line in data:
            if not line or line.startswith("#"):
                continue

            parts = line.split("|")
            if len(parts) < 7:
                continue

            registry, cc, rtype, start, value, date, status = parts[:7]

            if cc != "GH":
                continue

            if status not in ("allocated", "assigned"):
                continue

            try:
                if rtype == "ipv4":
                    cidrs = ipv4_to_cidrs(start, value)
                    for c in cidrs:
                        f4.write(c + "\n")

                elif rtype == "ipv6":
                    cidrs = ipv6_to_cidrs(start, value)
                    for c in cidrs:
                        f6.write(c + "\n")

            except Exception:
                continue

    print("Done.")
    print(f"Wrote {OUT_V4} and {OUT_V6}")


if __name__ == "__main__":
    main()
