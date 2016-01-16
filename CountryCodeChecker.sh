#!/bin/bash
echo "Subject: Malicious websites scanned results"
echo "From: onion@mysite.com"
#Navigate into curent day's directory in bro
cd /nsm/bro/logs/
str=$(date '+%F')
cd $str
#Dump all http logs and filter for individual country codes
zcat http*|awk {'print $9" --> "$3" --> "$1'}|grep -i -e "\.vn\>" -e "\.nl\>" -e "\.ch\>" -e "\.lk\>" -e "\.hk\>" -e "\.co.za\>" -e "\.de\>" -e "\.pw\>" -e "\.su\>" -e "\.ua\>"  -e "\.me\>" -e "\.biz\>" -e "\.ru\>" -e "\.pl\>" -e "\.in\>" -e "\.hu\>" -e "\.cn\>" -e "\.info\>" -e "\.cc\>"| sort| uniq > /tmp/ip2url1.txt
cd /opt/URLchecker/
#Create a list of only the websites to be scanned
cat /tmp/ip2url1.txt |awk {'print $1'} | sort | uniq> /tmp/countries2.txt
#Scan the websites in Virus Total
python urlChecker.py -i /tmp/countries2.txt -o /tmp/
rm /tmp/countries2.txt
#Check to see if sites were malicious, if not, terminate
test=$(python parseCheckerFile.py -i /tmp/VirusTotalResults.txt -o /tmp/Malicious4.txt)
if [ "$test" != "No malicious hits found" ]; then
	#Format a usable list of URLs.
	cat /tmp/Malicious4.txt | grep -i -e "\.vn\>" -e "\.nl\>" -e "\.ch\>" -e "\.lk\>" -e "\.hk\>" -e "\.co.za\>" -e "\.de\>" -e "\.pw\>" -e "\.su\>" -e "\.ua\>"  -e "\.me\>" -e "\.biz\>" -e "\.ru\>" -e "\.pl\>" -e "\.in\>" -e "\.hu\>" -e "\.cn\>" -e "\.info\>" -e "\.cc\>"| sort| uniq| awk {'print $2'} > /tmp/confirmed5.txt
	#Distinguish which IPs had visited the confirmed malicious websites
	while read line
	do
	cat /tmp/ip2url1.txt | grep $line >> /tmp/results6.txt
	done < /tmp/confirmed5.txt
	#Sort and remove redundancy in list of malicious hits
	cat /tmp/results6.txt | sort| uniq > /tmp/hosed7.txt
	rm /tmp/results6.txt
	rm /tmp/confirmed5.txt
	rm /tmp/ip2url1.txt
	rm /tmp/Malicious4.txt
	#Remove www. from list of urls also to lessen redundancy
	while read line
	do
	echo -e ${line#w*.} "\n" >> /tmp/hosedClean8.txt
	done < /tmp/hosed7.txt
	rm /tmp/hosed7.txt
	echo -e "\nThe following sites were visited today by these IP addresses and have been identified as being possibly malicious. Please further investigate:\n" 
	#Format list of malicious IPs to prep for locating each endpoint connected and at what time
	cat /tmp/hosedClean8.txt | awk {'print $1" "$2" "$3'} | sort | uniq | tail -n +2> /tmp/Ips9.txt
	while read line
	do
        	Times=($(cat /tmp/hosedClean8.txt | grep "$line" | awk {'print $5'}))
        	last=$(echo "${#Times[@]}")
        	end=${Times[$last-1]}
        	start=${Times[0]}
        	convStart=$(date -d @$start)
        	time1=$(date -d @$start +%s)
        	time2=$(date -d @$end +%s)
        	cat /tmp/hosedClean8.txt| grep $start | sort |awk {'print $1" "$2" "$3" "$4'} | tr '\n' ' '
        	echo $convStart
        	cat /tmp/VirusTotalResults.txt| grep -A3 `echo $line | awk {'print $1'}`| tail -n 1
        	let diff=$((-($time1-$time2)))
        	if [ $diff -gt 0 ]; then
                	echo "This connection persisted for $(($diff / 3600)) hours, $((($diff / 60)%60)) minutes, and $(($diff % 60)) seconds."
        	else
                	echo "This connection happened only once."
        	fi
        	echo ""
	done < /tmp/Ips9.txt
	rm /tmp/VirusTotalResults.txt
	rm /tmp/hosedClean8.txt
	rm /tmp/Ips9.txt
else
	echo "No malicious connections were made today."
	rm /tmp/ip2url1.txt
	rm /tmp/countries2.txt
	rm /tmp/VirusTotalResults.txt
fi
