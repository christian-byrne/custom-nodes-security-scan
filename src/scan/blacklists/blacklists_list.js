const request = require('request');

/*
{
    reference: "",
    title: title.,
    type: type.,
    mode: mode.,
    submode: submode.,
    comment: "",
    limit: -1
}
*/
var type = {default: "BadReputation", malware: "Malware", bad_reputation: "BadReputation", known_attacker: "KnownAttacker", spammer: "Spammer", phishing: "Phishing", cryptocurrencies: "CryptoCurrencies", hide_source: "HideSource", adware: "Adware", dga: "DGA", whitelist: "Whitelist"}
var title = {default: "Malicious Host",  bitcoin: "Bitcoin Node", miner: "Crypto Miner", spammer: "Spammer", phishing: "Phishing", proxy: "Proxy", tor: "Tor", ransomware: "Ransomware", zeus: "Zeus", web_proxy: "Web Proxy", browser_hijaking: "Browser Hijacking", cryptocurrency: "Cryptocurrency", cheap_domain: "Cheap Domain", get_my_ip: "Get my public ip", web_tor: "Web to Tor", superfish: "Superfish", shellcode: "Shellcode", adware: "Adware", whitelist: "Whitelist"}

var mode = {http_list: { regex: /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/gi, regex_check: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)$/i }, //Protocol http or https
            url_list: { regex: /[-a-zA-Z0-9@:%_\+.~#?&//=]{2,256}\.[a-z]{2,4}\b(\/[-a-zA-Z0-9@:%_\+.~#?&//=]*)?/gi, regex_check: /^[-a-zA-Z0-9@:%_\+.~#?&//=]{2,256}\.[a-z]{2,4}\b(\/[-a-zA-Z0-9@:%_\+.~#?&//=]*)?$/i }, //url without protocol
            domain_list: { regex: /[a-zA-Z0-9-]+\.[a-zA-Z0-9-\.]+/g, regex_check: /^[a-zA-Z0-9-_\.]+$/ },
            ip_list: { regex: /(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g, regex_check: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/},
            range_list: { regex: /(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/\d{1,2}/g, regex_check: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/\d{1,2}$/ }
}

var submode = { each_line: 1, extract_all: 2, custom_Query_for_Suspicious: 3, malc0de: 4 }

var private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "0.0.0.0/8"];

var blacklist_list = [
    //White List
    {
        reference: "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
        title: title.whitelist,
        type: type.whitelist,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "",
        limit: -1
   },
    
    {
        reference: "https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/white_list.txt",
        title: title.whitelist,
        type: type.whitelist,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "",
        limit: -1
   },

   {
        reference: "http://downloads.majestic.com/majestic_million.csv",
        title: title.whitelist,
        type: type.whitelist,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "",
        limit: 10000
    },

    //MALWARE
    //http://www.malwaredomainlist.com/mdlcsv.php OLD and no updates
    {
        reference: "https://urlhaus.abuse.ch/downloads/csv_online/",
        title: /,.*,.*,.*,.*,(.*)\",.*,/,
        type: type.malware,
        mode: mode.http_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },
    
    {
        reference: "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.csv",
        title: /,([\w\d- ]+),2/,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "Domain,",
        limit: -1
    },

    {
        reference: "https://cybercrime-tracker.net/ccamgate.php",
        title: title.default,
        type: type.malware,
        mode: mode.http_list,
        submode: submode.each_line,
        comment: "",
        limit: -1
    },

    {
        reference: "https://cybercrime-tracker.net/all.php",
        title: title.default,
        type: type.malware,
        mode: mode.url_list,
        submode: submode.each_line,
        comment: "",
        limit: -1
    },

    { 
        reference: "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: ""
    },

    {   // Surikata rules
        reference: "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.custom_Query_for_Suspicious,
        comment: "",
        limit: -1
    },

    {   // Nothing:(
        reference: "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist",
        title: title.default,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {   // Nothing:(
        reference: "https://feodotracker.abuse.ch/blocklist/?download=badips",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "https://www.malwaredomainlist.com/hostslist/hosts.txt",
        title: title.default,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "https://www.malwaredomainlist.com/hostslist/ip.txt",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1
    },

    {
        reference: "https://lists.malwarepatrol.net/cgi/getfile?receipt=f1417692233&product=8&list=dansguardian",
        title: title.default,
        type: type.malware,
        mode: mode.url_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    /* { //OLD
        reference: "http://www.nothink.org/blacklist/blacklist_malware_irc.txt",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },*/

    {   //Looks like extract_all but check it, it works better with each_line
        reference: "http://www.urlvir.com/export-hosts/",
        title: title.default,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 //In comment
    },

    {
        reference: "https://raw.githubusercontent.com/futpib/policeman-rulesets/master/examples/simple_domains_blacklist.txt",
        title: title.default,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
        title: title.ransomware,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 //In comment
    },

    {
        reference: "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
        title: title.ransomware,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 //In comment
    },

    {
        reference: "https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt",
        title: title.ransomware,
        type: type.malware,
        mode: mode.http_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 //In comment
    },

    {
        reference: "http://vxvault.net/URL_List.php",
        title: title.default,
        type: type.malware,
        mode: mode.http_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 //At beginning but no comment
    },

    {
        reference: "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
        title: title.zeus,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "https://zeustracker.abuse.ch/blocklist.php?download=badips",
        title: title.zeus,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "https://zeustracker.abuse.ch/monitor.php?filter=all",
        title: title.zeus,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1
    },

    {
        reference: "https://mirror.cedia.org.ec/malwaredomains/justdomains",
        title: title.default,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "",
        limit: -1
    },

    /*{ // DGA - not intresting
        reference: "http://data.netlab.360.com/feeds/dga/dga.txt",
        title: /(^\w*)/,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },*/

    {
        reference: "https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt",
        title: /used by ([\w/]*)/,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    /*{  //More than 850.000 lines, the progras gets frozen
        reference: "https://osint.bambenekconsulting.com/feeds/dga-feed.txt",
        title: /used by ([\w/]*)/,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#"
    },*/

    {
        reference: "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt",
        title: /used by ([\w/]*)/,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {   //Port
        reference: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        title: /\d,([A-Z]\w*)/,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {   //Check old
        reference: "https://rules.emergingthreats.net/open/suricata/rules/botcc.rules",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "#",
        limit: -1
    },

    { 
        reference: "https://malc0de.com/bl/ZONES",
        title: title.default,
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.extract_all,
        comment: "//",
        limit: -1 //In comment
    },

    {
        reference: "https://raw.githubusercontent.com/Neo23x0/signature-base/39787aaefa6b70b0be6e7dcdc425b65a716170ca/iocs/otx-c2-iocs.txt",
        title: /(([ ;][A-Z-a-gi-z]\w*)+)/,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 //In comment
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/computrace.txt",
        title: "Computrace",
        type: type.malware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1
    },

    {
        reference: "http://malc0de.com/bl/IP_Blacklist.txt",
        title: title.default,
        type: type.malware,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "//",
        limit: -1
    },

    {
        reference: "http://malc0de.com/rss/",
        title: title.default,
        type: type.malware,
        mode: mode.url_list,
        submode: submode.malc0de,
        comment: "",
        limit: -1
    },
   // MALWARE END

    // KNOWN ATTACKER

    {
        reference: "https://www.dshield.org/api/threatlist/univmichigan",
        title: "University of Michigan scans.io zmap scans",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },
    
    {
        reference: "https://www.dshield.org/api/threatlist/shodan",
        title: "Scanners Operated by the ShodanHQ Project",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },
    
    {
        reference: "https://www.dshield.org/api/threatlist/rapid7sonar",
        title: "Rapid 7 Project Sonar scanners",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },
    
    {
        reference: "https://www.dshield.org/api/threatlist/onyphe",
        title: "Scanners Operated by Onyphe.io",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },
    
    {
        reference: "https://www.dshield.org/api/threatlist/ipip",
        title: "IPIP Security / Research scanners security.ipip.net",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://www.dshield.org/api/threatlist/erratasec",
        title: "Errata Security Masscan",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://www.dshield.org/api/threatlist/cybergreen",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://cinsscore.com/list/ci-badguys.txt", //The web is limiting to 15.000 IPs max
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://www.dshield.org/api/threatlist/censys",
        title: "Censys Research Scanners",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://www.dshield.org/api/threatlist/blindferret",
        title: "Project Blindferret zmap scanners",
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://lists.malwareworld.com/blacklist",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://www.badips.com/get/list/any/2?age=7d",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "http://lists.blocklist.de/lists/all.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    

    {
        reference: "http://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1month old
    },

    {
        reference: "http://cinsscore.com/list/ci-badguys.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {   //Did not load, check, tooks a lot to load
        reference: "http://www.cruzit.com/xwbl2txt.php",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://dataplane.org/dnsrd.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/dnsrdany.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/dnsversion.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/sipinvitation.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/sipquery.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/sipregistration.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/sshclient.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/sshpwauth.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {
        reference: "https://dataplane.org/vncrfb.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // to 1 week old
    },

    {   // Some domains referer to the IP
        reference: "http://feeds.dshield.org/top10-2.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "http://blocklist.greensnow.co/greensnow.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "http://report.rutgers.edu/DROP/attackers",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "http://www.voipbl.org/update/",
        title: title.default,
        type: type.known_attacker,
        mode: mode.range_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "http://www.nothink.org/blacklist/blacklist_snmp_week.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // Date in comment
    },

    {
        reference: "http://www.nothink.org/blacklist/blacklist_ssh_week.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // Date in comment
    },

    {   // Telnetweek was too much
        reference: "http://www.nothink.org/blacklist/blacklist_telnet_day.txt",
        title: title.default,
        type: type.known_attacker,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // Date in comment
    },

    // KNOWN ATTACKER END

    // BAD REPUTATION
    {
        reference: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        title: title.default,
        type: type.default,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 //In comment
    },
    
    {   //Habria que hailitar dominios de un solo nivel TODO
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/domain.txt",
        title: title.cheap_domain,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/dynamic_domain.txt",
        title: title.cheap_domain,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/free_web_hosting.txt",
        title: title.cheap_domain,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/ipinfo.txt",
        title: title.get_my_ip,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {   // Location
        reference: "https://reputation.alienvault.com/reputation.generic",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://isc.sans.edu/feeds/suspiciousdomains_Low.txt",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },

    {
        reference: "https://www.maxmind.com/en/high-risk-ip-sample-list",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commetnt
    },

    {
        reference: "http://www.talosintelligence.com/feeds/ip-filter.blf",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "https://www.turris.cz/greylist-data/greylist-latest.csv",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {   // Gives the real source
        reference: "http://malwaredomains.lehigh.edu/files/domains.txt",
        title: title.default,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // usefull in line
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/web_shells.txt",
        title: title.shellcode,
        type: type.bad_reputation,
        mode: mode.url_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // usefull in line
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/parking_site.txt",
        title: title.shellcode,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // usefull in line
    },

    /*{ Composed by other blacklists, have 2 years older domiains
        reference: "http://mirror1.malwaredomains.com/files/domains.txt",
        title: title.shellcode,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // usefull in line
    },*/

    // BAD REPUTATION END

    // HIDE SOURCE
    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_1d.ipset",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyrss_1d.ipset",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyspy_1d.ipset",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ri_web_proxies_30d.ipset",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies_1d.ipset",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {   // Port
        reference: "http://multiproxy.org/txt_all/proxy.txt",
        title: title.proxy,
        type: type.hide_source,
        mode: mode.ip_list, //:port
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },
    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/anonymous_web_proxy.txt",
        title: title.web_proxy,
        type: type.hide_source,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commment
    },

    {
        reference: "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1",
        title: title.tor,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in commetn
    },

    {
        reference: "https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv",
        title: title.tor,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // Date in commetn
    },

    {
        reference: "https://www.dshield.org/api/threatlist/torexit/",
        title: title.tor,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // Date "in line"
    },

    {
        reference: "https://check.torproject.org/exit-addresses",
        title: title.tor,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // Date "in line"
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/onion.txt",
        title: title.web_tor,
        type: type.hide_source,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date "in line"
    },

    {
        reference: "https://www.dan.me.uk/tornodes",
        title: title.tor,
        type: type.hide_source,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "",
        limit: -1 // Date "in line"
    },
    // HIDE SOURCE END

    // SPAMMER
    {
        reference: "https://panwdbl.appspot.com/lists/shdrop.txt",
        title: title.spammer,
        type: type.spammer,
        mode: mode.range_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://panwdbl.appspot.com/lists/shedrop.txt",
        title: title.spammer,
        type: type.spammer,
        mode: mode.range_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://panwdbl.appspot.com/lists/shdrop.txt",
        title: title.spammer,
        type: type.spammer,
        mode: mode.range_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt",
        title: title.spammer,
        type: type.spammer,
        mode: mode.range_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },

    {
        reference: "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
        title: title.spammer,
        type: type.spammer,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },
    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset",
        title: title.spammer,
        type: type.spammer,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },

    {
        reference: "http://sblam.com/blacklist.txt",
        title: title.spammer,
        type: type.spammer,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    // SPAMMER END

    // PHISHING
    {
        reference: "https://openphish.com/feed.txt",
        title: title.phishing,
        type: type.phishing,
        mode: mode.http_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },

    {
        reference: "http://data.phishtank.com/data/online-valid.csv",
        title: title.phishing,
        type: type.phishing,
        mode: mode.http_list,
        submode: submode.each_line,
        comment: "",
        limit: -1 // No date
    },
    // PHISHING END

    { //Browser Hijacking
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/browser_hijacking.txt",
        title: title.browser_hijaking,
        type: type.bad_reputation,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },
    //Browser Hijacking end

    // CRYPTOCURRENCIES
    {
        reference: "https://www.dshield.org/api/threatlist/miner/",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.ip_list,
        submode: submode.extract_all,
        comment: "#",
        limit: -1 // Date in comment
    },

    {
        reference: "https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/list.txt",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    
    {
        reference: "https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/list_browser.txt",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    
    {
        reference: "https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/list_optional.txt",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    
    {
        reference: "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    
    {
        reference: "https://zerodot1.gitlab.io/CoinBlockerLists/hosts",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    
    {
        reference: "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_optional",
        title: title.miner,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },

    {
        reference: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bitcoin_nodes_1d.ipset",
        title: title.bitcoin,
        type: type.cryptocurrencies,
        mode: mode.ip_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/crypto_mining.txt",
        title: title.cryptocurrency,
        type: type.cryptocurrencies,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },
    // CRYPTOCURRENCIES END

    // ADWARE
    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/superfish.txt",
        title: title.superfish,
        type: type.adware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // Date in comment
    },

    {
        reference: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/pup.txt",
        title: title.adware,
        type: type.adware,
        mode: mode.domain_list,
        submode: submode.each_line,
        comment: "#",
        limit: -1 // No date
    },
]

function get_maltrail_static_malware(){
    var options = {
        method: 'GET',
        url: "https://github.com/stamparm/maltrail/tree/master/trails/static/malware",
        gzip: true,
        headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:59.0) Gecko/20100101 Firefox/59.0' }
      };
    request(options, function (error, response, body) {
        if (error){
            console.log('Error: Downloading master github page of static maltrail alware blacklists!! -- ', error);
        }
        if (body){
            urlmtchs = body.match(/\/stamparm\/maltrail\/blob\/master\/trails\/static\/malware\/[\w\d\-]+\.txt/g);
            urlmaster = "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/"
            urlmtchs.forEach(function(url) {
                nametxt = url.split("/").slice(-1)[0];
                name = nametxt.split(".")[0];
                url = urlmaster + nametxt;
                bl_elem = {
                    reference: url,
                    title: name.charAt(0).toUpperCase() + name.slice(1),
                    type: type.malware,
                    mode: mode.domain_list,
                    submode: submode.each_line,
                    comment: "#",
                    limit: -1
                };
                blacklist_list.push(bl_elem);
            });
        }
    });
}
// get_maltrail_static_malware();

exports.blacklist_list = blacklist_list;
exports.types = type;
exports.modes = mode;
exports.submodes = submode;
exports.titles = title;
exports.private_ranges = private_ranges;

// Adblock: Partes de la url que detecta adblock y bloquea
// https://easylist-downloads.adblockplus.org/easylist.txt

