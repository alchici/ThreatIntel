def createYARA(strings, hashes):

    result_strings = ""
    i = 1

    for string in strings:
        result_strings += "\t${} = \"{}\"\n".format(i,string)
        i += 1
    
    result_hashes = ""
    i = 1

    for hash in hashes:
        result_hashes += """ or
        hash.sha256(0, filesize) == \"{}\"""".format(hash)
        i += 1
    
    template = '''import "hash"
    
rule IOCs
{{
    strings:
{}    condition:
        any of them{}
}}'''.format(result_strings, result_hashes)
    
    print(template)
    
    with open('./rules/yara.yar', 'w') as archivo_modificado:
        archivo_modificado.write(template)

def createSysmon(exes, dlls, regs, comms):

    result_exes = ""

    if exes != []:
        result_exes += "\t\t<ProcessCreate onmatch=\"include\">\n"
        for exe in exes:
            result_exes += "\t\t\t<Image condition=\"contains\">{}</Image>\n".format(exe)
        result_exes += "\t\t</ProcessCreate>"
    
    result_dlls = ""

    if dlls != []:
        result_dlls += "\t\t<ImageLoad onmatch=\"include\">\n"
        for dll in dlls:
            result_dlls += "\t\t\t<ImageLoaded condition=\"contains\">{}</ImageLoaded>\n".format(dll)
        result_dlls += "\t\t</ImageLoad>"

    result_regs = ""

    if regs != []:
        result_regs += "\t\t<RegistryEvent onmatch=\"include\">\n"
        for reg in regs:
            result_regs += "\t\t\t<TargetObject condition=\"contains\">{}</TargetObject>\n".format(reg)
        result_regs += "\t\t</RegistryEvent>"

    result_comms = ""

    if comms != []:
        result_comms += "\t\t<ProcessCreate onmatch=\"include\">\n"
        for comm in comms:
            result_comms += "\t\t\t<CommandLine condition=\"contains\">{}</CommandLine>\n".format(comm)
        result_comms += "\t\t</ProcessCreate>"

    template = '''<Sysmon schemaversion="10.4">

    <HashAlgorithms>md5,sha256</HashAlgorithms>

    <EventFiltering>

{}

{}

{}

{}

    </EventFiltering>

</Sysmon>'''.format(result_exes,result_dlls,result_regs,result_comms)

    print(template)

    with open('./rules/sysmon.xml', 'w') as archivo_modificado:
        archivo_modificado.write(template)

def createSuricata(ips, domains):
    result_ips = ""
    i = 1000001

    if ips != []:
        for ip in ips:
            result_ips += "alert tcp $HOME_NET any -> {} any (msg:\"TCP traffic from HOME_NET to {}\"; sid:{}; rev:1;)\n".format(ip,ip,i)
            i += 1
            result_ips += "alert udp $HOME_NET any -> {} any (msg:\"UDP traffic from HOME_NET to {}\"; sid:{}; rev:1;)\n".format(ip,ip,i)
            i += 1
    
    result_dns = ""
    result_http = ""

    if domains != []:
        for domain in domains:
            result_dns += "alert dns $HOME_NET any -> any any (dns.query; content:\"{}\"; nocase; msg:\"DNS query to {} from HOME_NET\"; sid:{}; rev:1;)\n".format(domain,domain,i)
            i += 1
            result_http += "alert http $HOME_NET  any -> any any (http.host; content:\"{}\"; nocase; msg:\"HTTP connection to {} from HOME_NET\"; sid:{}; rev:1;)\n".format(domain,domain,i)
            i += 1

    template = ''' #IP

{}
# Domain DNS

{}
# Domain HTTP

{}'''.format(result_ips,result_dns,result_http)
    
    print(template)

    with open('./rules/suricata.rules', 'w') as archivo_modificado:
        archivo_modificado.write(template)

def createSigma(exes,dlls,regs,comms):

    result_exes = ""

    if exes != []:
        result_exes += "\t\t\tImage|endswith:\n"
        for exe in exes:
            result_exes += "\t\t\t\t- '{}'\n".format(exe)
    
    result_dlls = ""

    if dlls != []:
        result_dlls += "\t\t\tImageLoaded|endswith:\n"
        for dll in dlls:
            result_dlls += "\t\t\t\t- '{}'\n".format(dll)

    result_regs = ""

    if regs != []:
        result_regs += "\t\t\tTargetObject|contains:\n"
        for reg in regs:
            result_regs += "\t\t\t\t- '{}'\n".format(reg)

    result_comms = ""

    if comms != []:
        result_comms += "\t\t\tCommandLine|contains:\n"
        for comm in comms:
            result_comms += "\t\t\t\t- '{}'\n".format(comm)


    template = '''title: Threat Intel Automatic Sigma Rules
id: 3c5a0085-daca-45ce-af94-2d5495039ada
status: experimental
description: Sigma rules generated automatically by Threat Intelligence Report Generator
author: Alejandro Miguel Chirivella Ciruelos
logsource:
    product: windows
detection:
    selection:
{}{}{}{}    condition: selection
level: high'''.format(result_exes,result_dlls,result_regs,result_comms)
    
    print(template)

    with open('./rules/sigma.yml', 'w') as archivo_modificado:
        archivo_modificado.write(template)

def createRules(data):

    yara_strings = []
    yara_hashes = []
    sysmon_exes = []
    sysmon_dlls = []
    suricata_ips = []
    suricata_domains = []
    sysmon_regs = []
    sysmon_comms = []

    for ioc in data.iocs:
        parts = ioc.split(":")
        tipo = parts[0]
        valor = ":".join(parts[1:]).strip()
        
        if tipo != "Hash":
            yara_strings.append(valor)  
        if tipo == "Hash":
            yara_hashes.append(valor)
        if tipo == "EXE":
            sysmon_exes.append(valor)
        if tipo == "DLL":
            sysmon_dlls.append(valor)
        if tipo == "Registry":
            sysmon_regs.append(valor)
        if tipo == "Command":
            sysmon_comms.append(valor)
        if tipo == "IP":
            suricata_ips.append(valor)
        if tipo == "Domain":
            suricata_domains.append(valor)

    createYARA(yara_strings, yara_hashes)
    createSysmon(sysmon_exes, sysmon_dlls, sysmon_regs,sysmon_comms)
    createSuricata(suricata_ips, suricata_domains)
    createSigma(sysmon_exes, sysmon_dlls, sysmon_regs,sysmon_comms)

if __name__ == "__main__":
    # createYARA(["a","b","asdasda"],["adsqadsacsdacadsadsva","dacko4'3r3ienf230qnd"])
    createSysmon(["cmd.exe","test.exe"],["a.dll","testest.dll"],["\HKEY\LOCAL\Test"],["test --aa"])
    # createSuricata(["1.1.1.1","192.1.2.3"],["www.google.es","www.asd.pl"])
    createSigma(["cmd.exe","test.exe"],["a.dll","testest.dll"],["\HKEY\LOCAL\Test"],["test --aa"])