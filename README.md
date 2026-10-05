# EHAX

i have initiated the project with use of regex to understand the patterns of log file data and interpret the username ,ips , timestamp, pid etc , created patterns for sudo , session open / closed , ssh login 

then designed brute force structure to detect suspicious things which consists of 4 rules 
rule no 1 = 8 failed login attempts within a minute 
rule no 2 = 10 failed login attempts within 15 minutes
rule no 3 = same user 
rule no 4 = invalid user trying to login again nd again for the same ip address
