# Geofeeds

Geofeeds are references to CSV files in RDAP links as defined by RFC 9877.

## Parameters

When the `-O geofeed` output type is used, any Geofeed link found in the response is downloaded.

```bash
$ rdap -O geofeed  81.93.181.144
2026-08-06T15:01:55.873639Z  INFO rdap: query type is IpV4 Address Lookup for value '81.93.181.144'
2026-08-06T15:01:55.874143Z  INFO rdap::query: Downloading geofeed from: https://geo.ip.gin.ntt.net/geofeeds/geofeeds.csv
2026-08-06T15:01:56.047816Z  INFO rdap::query: Geofeed downloaded to: /var/home/andy/Downloads/geofeed/geofeeds.csv
```

Unless the `-G` parameter is specified, the file will be downloaded to a "geofeeds" directory in the users "Downloads" folder,
or the current directory if no "Downloads" folder can be determined.

The `-G` parameter specifies a specific file, not a directory.

```bash
andy@bluefin ~/p/icann-rdap.gh-pages (gh-pages)> rdap -O geofeed -G my-feed.csv 81.93.181.144
2026-08-06T15:00:34.556864Z  INFO rdap: query type is IpV4 Address Lookup for value '81.93.181.144'
2026-08-06T15:00:34.847558Z  INFO rdap::query: Downloading geofeed from: https://geo.ip.gin.ntt.net/geofeeds/geofeeds.csv
2026-08-06T15:00:35.480440Z  INFO rdap::query: Geofeed downloaded to: my-feed.csv
```

## Smart Append

When a file is downloaded to the geofeeds directory, the filename in the HTTP path of the link is used.
If a file by that name already exists, the downloaded file is appended to the existing file.

The same is true of a file specified with the `-G` parameter.

In both cases, if the existing file does not end with the platform's line termination characters
(i.e., "\r\n" for Windows, "\n" for all others), then the line termination characters are
appended to the file before the downloaded content is appended to the file.
