# mydns
written by Gianluca Mazzini gianluca@mazzini.org
started in 2015

dns filtering with blacklist, whitelist, common black list and profilation

mydns receive dns request and checks if the domain matches a whitelist, then a black list, then a common black list, the it provides a dns solution.

configuration file are space of \n separated fields and are supposed to be in /mydns
three configuration file are necessary: mydns.boot with starting parameters, mydns.conf with configuration action for any source query, commonblacklist for commonblacklist domains

mydns.boot which contains: dns listen port, basic dns ipv4 address for dns resolving, first dns backup ipv4 address for dns resolving, second dns backup ipv4 address for dns solving, splash ipv4 address for blocking actions returned as dns ipv4 address resolution, splash ipv6 address for blocking actions returned as dns ipv6 address resolution

mydns.conf a list of lines each containing: ipv4 address, cidr, identification as a id string for line reference, commonblacklist flag with 0 for no and 1 for yes, whithelist espressed as a list like {domain/}\ where \ it the terminator and an example is google.com/google.it/yahoo.com/\ or a minimum string of \, blacklist espressed as the whitelist

commonblacklist a \n list of all th domains to be commonly blocked. A simple way to create or refrest it is from http://dsi.ut-capitole.fr/blacklists/index_en.php by selecting interesting category and by skipping eventually ip address which cannot be used in dns query. As a simple example to create please check mydownload bash script

to compile the daemon please consider the makefile example and kust use make
