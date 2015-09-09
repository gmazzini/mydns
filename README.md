# mydns
written by Gianluca Mazzini gianluca@mazzini.org
started in 2015

dns filtering with blacklist, whitelist, common black list and profilation

mydns receives dns request and checks if the domain matches a whitelist, then a black list, then a common black list, the it provides a dns solution.

configuration files are space or \n separated fields and are supposed to be in /mydns

three configuration file are necessary: mydns.boot with starting parameters, mydns.conf with configuration action for any source query, commonblacklist for commonblacklist domains

mydns.boot contains: dns listen port, basic dns ipv4 address for dns resolving, first dns backup ipv4 address for dns resolving, second dns backup ipv4 address for dns solving, password for TXT query command, splash ipv4 address for blocking actions returned as dns ipv4 address resolution, splash ipv6 address for blocking actions returned as dns ipv6 address resolution

mydns.conf a list of lines each containing: ipv4 address, cidr, identification as a id string for line reference, commonblacklist flag with 0 for no and 1 for yes, whithelist espressed as a list like {domain/}\ where \ it the terminator and an example is google.com/google.it/yahoo.com/\ or a minimum string of \, blacklist espressed as the whitelist

commonblacklist a \n list of all th domains to be commonly blocked. A simple way to create or refrest it is from http://dsi.ut-capitole.fr/blacklists/index_en.php by selecting interesting category and by skipping eventually ip address which cannot be used in dns query. As a simple example to create please check mydownload bash script

mydns support profilation for a single ipv4, where ipv4 must be in the range 10.32.0.0/12, such an ipv4 is assigned to a class 127.127.A.B/32 address that should be present in mydns.conf and is processed with the filtering action assigned to that translated address

to compile the daemon please consider the makefile example and kust use make

command may be given by usung a dns query with TXT mode and the password in mydns.boot configuration file, in the following example the password is set to xxxxx
example of command is dig @127.0.0.1 +short -t TXT cmd/xxxxx/stats/10.32.4.0/

list of commands

cmd/&lt;password&gt;/reload/ for runtime mydns.conf reloading

cmd/&lt;password&gt;/recbl/ for runtime commonblacklist reloading

cmd/&lt;password&gt;/stats/&lt;ipv4&gt;/ to obtain for such an ipv4, the reference class as ipv4/cidr, the id, the number of query processed and filtered

cmd/&lt;password&gt;/status/ to obtain the demon uptime and some statistics like: the total number of query, the total number of splash response due to filtering, the number of query malformed (i.e. with not correct header) the number of query outofscope (i.e. with ipv4 address not in mydns.conf)

cmd/&lt;password&gt;/insert/&lt;ipv4&gt;/127.127.A.B/ to insert the IP in the 127.127.A.B/32 class, note that ipv4 address must be in the range 10.32.0.0/12

cmd/&lt;password&gt;/delete/&lt;ipv4&gt;/ to delete the eventually present profilation for such an ipv4

cmd/&lt;password&gt;/class/&lt;ipv4&gt;/ to retrive the eventyally present profilation class for a given ipv4
