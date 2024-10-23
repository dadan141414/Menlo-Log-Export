Examples
Here are some examples using the Python 3 script:
To view detailed help for the Python 3 script.
log_fetch.py -h

To fetch web logs using the log_fetch_py3.py script.
log_fetch.py [-h] [-o OUTPUT] [-d] [-s STARTTIME] [-e ENDTIME] [-f {CEF,JSON,KVP,CSV,LEEF}] [-t{'web','safemail','audit','smtp','attachment','dlp'}] [-host HOST] [-a APPEND] [-q QUERY] token

This will fetch web logs in CEF format with string source=acme from start time 2020-08-1408:00:00 UTC to end time 2020-08-16 09:00:00. This is output to data.txt.
log_fetch.py -t web -f CEF -o data.txt -s 20200814080000 -e20200816090000 -a 'source=acme' thisismysecrettoken

Fetch web logs in JSON format that match the query ‘domain LIKE “%google%”’ (any domain that contains “google”) from start time 2021-03-14 08:00:00 UTC to end time2021-03-16 09:00:00 and output to data.txt.
log_fetch.py -t web -f JSON -o data.txt -s 20210314080000-e 20210316090000 -q 'domain LIKE "%google%"'thisismysecrettoken

Fetch web logs in JSON format that match the query ‘interval=1d’ (occuring in the past 1d) and output to data.txt.
log_fetch.py -t web -f JSON -o data.txt -q 'interval=1d' thisismysecrettoken
