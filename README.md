# CVEParser
CVEParser was written for automated searches for Common Vulnerability and Exposures(CVE) as collected by NVD.
The parser will by default collect the most recent CVE collection as posted [Here!](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED)


## Requirements
CVEParser __must__ run on Python3.7 or later! This is due to a change in handling timezone data in datetime.

## Usage
Default run can be done without any parameters.

```CVEParser.py```

To view CVSSv2 or CVSSv3 information add one or more of the relevant options

```CVEParser.py -cvss2```

In some situations it is more preferable to run against a local copy of the .gz file

```CVEParser.py ./CVEParser.py -f 34345c35a5ceb7fca8166f432a527a49.gz --sha256 176312859669a578f9bcec1e208fb4e5c66569c7d300611be7b1cc4a8eb93fa8 --filter-list filter.txt -cvss2```

The _-s_ or _--short-list_ option will give a less verbose presentation of the output data and can be used in any mode.

```CVEParser.py --short-list```
