# Bind query log statistics generator

Produces a variety of statistics from one or more query logs passed on the command line.

# Usage:
<pre>
$ ./dnsrecon.py -h
usage: dnsrecon.py [-h] [--matrix] [--histogram] [--count Count]
                   [--excludeip [IP Address [IP Address ...]]]
                   [--excludenet [Network [Network ...]]]
                   [--domains [Domain [Domain ...]]] [--starttime Start Time]
                   [--endtime End Time]
                   [Logfile [Logfile ...]]

DNS Statistics Processor

positional arguments:
  Logfile               List of Bind query logs to process

optional arguments:
  -h, --help            show this help message and exit
  --matrix              Print client to domain resolution info
  --histogram           Print histogram of queries
  --count Count         Number of entries to display
  --excludeip [IP Address [IP Address ...]]
                        IPs to exclude from resolution matrix
  --excludenet [Network [Network ...]]
                        Networks to exclude from resolution matrix
  --domains [Domain [Domain ...]]
                        Create statistics for specific domains
  --starttime Start Time
                        Create statistics from this time forward
  --endtime End Time    Process statistics until this period of time
</pre>

# Sample Output:

$ dnsrecon.py /var/log/query.log* --domains prefetch.net foo.com --exclude 1.1.1.1 2.2.2.2 --histogram --matrix
<pre>
Processing logfile /var/log/query.log.1
Processing logfile /var/log/query.log.2
Processing logfile /var/log/query.log.3
Processing logfile /var/log/query.log.4

Summary for 21-Sep-2016 00:00:00.001 - 21-Sep-2016 23:59:59.991
  Total queries processed : 1328499
  A      records requested : 683201
  AAAA   records requested : 570441
  SRV    records requested : 66922
  SOA    records requested : 3094
  MX     records requested : 3069
  ANY    records requested : 1060
  IXFR   records requested : 434
  TXT    records requested : 257
  PTR    records requested : 15
  NS     records requested : 6

Top  100  DNS names requested:
  prefetch.net : 81379
  sheldon.prefetch.net : 75244
  penny.prefetch.net : 54637
  ..... 

Top  100  DNS clients:
  leonard :  103680
  raj :  92486
  howard : 32456
  bernadette : 12324
  ..... 
 
Queries per minute:
  00: ******************* (149807)
  01: ******************* (149894)
  02: ******************************* (239495)
  03: *********************************************** (356239)
  04: ********************************************** (351916)
  05: ********************************************* (346121)
  06: ************************************************ (362635)
  07: ************************************************** (377293)
  08: ********************************************* (343376)
  09: ********************** (169213)
  10: ****************************** (229027)
  11: ****************** (140477)
  12: ****************** (139954)
  13: ****************** (135871)
  14: ****************** (137822)
  15: ****************** (138635)
  16: ****************** (137310)
  17: ****************** (137466)
  18: ***************** (134564)
  19: ****************** (138332)
  20: ***************** (135392)
  21: ****************** (137407)
  22: ****************** (137424)
  23: ****************** (140056)
  24: ****************** (139497)
  25: ****************** (137237)
  26: ****************** (137737)
  27: ****************** (139208)
  28: ***************** (135199)
  29: ****************** (135959)
  30: ****************** (140801)
  31: ****************** (142486)
  32: ****************** (143127)
  33: ****************** (141277)
  34: ****************** (142003)
  35: ****************** (143132)
  36: ******************* (144369)
  37: ****************** (140977)
  38: ****************** (139053)
  39: ****************** (139480)
  40: ****************** (138179)
  41: ****************** (138187)
  42: ****************** (139191)
  43: ****************** (138635)
  44: ****************** (141588)
  45: ****************** (139573)
  46: ****************** (140661)
  47: ******************* (149312)
  48: ****************** (141697)
  49: ******************* (149304)
  50: ****************** (142139)
  51: ****************** (142245)
  52: ****************** (139075)
  53: ******************* (148803)
  54: ******************* (144888)
  55: ****************** (136482)
  56: ****************** (139917)
  57: ****************** (141297)
  58: ****************** (137870)
  59: ****************** (141526)

Queries per hour:
  00: ********* (325710)
  01: ********** (363579)
  02: ******** (304630)
  03: ******** (302274)
  04: ******** (296872)
  05: ******** (295430)
  06: ******** (309823)
  07: ********* (347762)
  08: ********* (350258)
  09: ********** (371690)
  10: *********** (397320)
  11: ************ (444637)
  12: ************ (448091)
  13: *********** (419678)
  14: ************************************************** (1765424)
  15: ************ (449459)
  16: ********* (338963)
  17: ********* (338588)
  18: ********* (340240)
  19: ********* (342471)
  20: ********* (332453)
  21: ********* (340441)
  22: ********** (377252)
  23: ********* (334792)
  
Domain to client resolution matrix:

prefetch.net
  |-- leonard 87656
  |-- howard 23456
  |-- bernadette 3425
  .....
</pre>
