import os, re
from test import getGroup
from navlayer import killChainSVG

def clean():
    os.system('rm -r generated')
    os.system('cp -r template generated')

def compile():
    os.system('cd generated && pdflatex main.tex')


def createTTP(subtechniques):
    subtechniques = sorted(subtechniques, key=lambda x: x)
#     table_begin = '''\\begin{table}[H]
# \\centering
# \\begin{adjustbox}{max width=\\textwidth}
# \\begin{tabular}{|c|c|c|}
# \\hline
# \\textbf{Tactic} & \\textbf{Technic} & \\textbf{Sub-technic} \\\\ \\hline'''

    table_begin = r'''\begin{center}
\begin{longtable}[H]{|C{0.3\textwidth}|C{0.3\textwidth}|C{0.3\textwidth}|}
\hline \textbf{Tactics} & \textbf{Techniques} & \textbf{Sub-techniques} \\ \hline'''
    
#     table_end = '''\\end{tabular}
# \\end{adjustbox}
# \\caption{TTPs associated with the intelligence}
# \\end{table}'''

    table_end = r'''\caption{TTPs associated with the intelligence}
\end{longtable}
\end{center}
\normalsize'''
    processed = []
    for subtechnique in subtechniques:
        x = re.findall("(T\d+[\.\d]*)", subtechnique) 
        if len(x) == 2:
            i1 = subtechnique.find(x[0])
            i2 = subtechnique.find(x[1])

            processed.append([subtechnique[:i1].strip(),subtechnique[i1:i2].strip(),subtechnique[i2:].strip()])
            
        else:
            i1 = subtechnique.find(x[0])
            y = re.findall("No sub-techniques", subtechnique)
            i2 = subtechnique.find(y[0])

            processed.append([subtechnique[:i1].strip(),subtechnique[i1:i2].strip(),subtechnique[i2:].strip()])
    

    result = table_begin

    for technique in processed:

        result += '\n{} & {} & {} \\\\ \\hline'.format(technique[0],technique[1],technique[2])
    
    result += '\n' + table_end

    if subtechniques != []:
        return result, processed
    else:
        return "", []


def createGroups(groups):

    item_begin = '\\begin{itemize}'
    item_end = '\\end{itemize}'

    result = item_begin

    for group in groups:
        info = getGroup(group)
        # print(info["description"])
        # print(info["aliases"])

        alias = ''

        for a in info["aliases"]:
            alias += a + ', '
        
        alias = alias.strip()[:-1]

        pattern = r'\(Citation:\s[^\)]+\)'

        modified_description = re.sub(pattern, '', info["description"])

        result += '''\\item \\textbf{{{}}}\\begin{{itemize}}
\\item \\textbf{{Description}}: {}
\\item \\textbf{{Alias}}: {}
\end{{itemize}}
'''.format(info["name"], modified_description, alias)
        
    
    result += item_end
    
    if groups != []:
        return result
    else:
        return ""

def createIocs(iocs):
#     table_start = r'''\begin{table}[H]
# \centering
# \begin{adjustbox}{max width=\textwidth}
# \begin{tabular}{|c|c|}
# \hline
# \textbf{Type} & \textbf{IoC} \\ \hline'''
    
    table_start = r'''\begin{longtable}[H]{|C{0.15\textwidth}|C{0.85\textwidth}|}
\hline \textbf{Type} & \textbf{IoC} \\ \hline'''
#     table_end = r'''\end{tabular}
# \end{adjustbox}
# \caption{IoCs associated with the intelligence}
# \end{table}'''
    table_end = r'''\caption{IoCs associated with the intelligence}
\end{longtable}
\normalsize'''

    result = table_start

    for ioc in iocs:
        parts = ioc.split(":")
        tipo = parts[0]
        valor = ":".join(parts[1:]).strip()
        if tipo == "Hash":
            valor = "\wrap{" + valor + "}"
            result += '\n {} & {}\\\\ \\hline'.format(tipo, valor)
        else:
            result += '\n {} & {}\\\\ \\hline'.format(tipo, valor.replace("\\", "\\textbackslash{}").replace("&", "\\&").replace("_", "\\_"))

    result += table_end

    if iocs != []:
        return result
    else:
        return ""
    

def createKillChain(TTP):

    techniques = []

    for t in TTP:
        x = re.findall("(T\d+[\.\d]*)", t[1])
        techniques.append(x[0])

    killChainSVG(techniques)

    os.system('cp output.png ./generated/images')

    result = r'''\begin{figure}[H]
\centering
\includegraphics[width=1\linewidth]{images/output.png}
\caption{MITRE Kill Chain}
\label{fig:enter-label}
\end{figure}'''

    if TTP != []:
        return result
    else:
        return ""
    

def write(title, author, description, groups, TTP, iocs, killchain):

    def match(arg):
        if arg.group() == 'TTP':
            return TTP
        elif arg.group() == 'GROUPS':
            return groups
        elif arg.group() == 'IOCS':
            return iocs
        elif arg.group() == 'DESCRIPTION':
            return description
        elif arg.group() == 'TITLE':
            return title
        elif arg.group() == 'AUTHOR':
            return author
        elif arg.group() == 'KILLCHAIN':
            return killchain
        
    with open('./template/carpeta/seccion1.tex', 'r') as archivo:
        contenido = archivo.read()

    contenido = re.sub('TTP', match, contenido)
    contenido = re.sub('GROUPS', match, contenido)
    contenido = re.sub('IOCS', match, contenido)
    contenido = re.sub('DESCRIPTION', match, contenido)
    contenido = re.sub('KILLCHAIN', match, contenido)

    with open('./generated/carpeta/seccion1.tex', 'w') as archivo_modificado:
        archivo_modificado.write(contenido)

    with open('./template/carpeta/portada_indice.tex', 'r') as archivo:
        contenido = archivo.read()

    contenido = re.sub('TITLE', match, contenido)
    contenido = re.sub('AUTHOR', match, contenido)

    with open('./generated/carpeta/portada_indice.tex', 'w') as archivo_modificado:
        archivo_modificado.write(contenido)

def process(obj):
    clean()
    groups = createGroups(obj.groups)
    (TTP, arrayTTP) = createTTP(obj.subtechniques)
    iocs = createIocs(obj.iocs)
    title = obj.title.replace('\n','\\\\')
    author = obj.author.replace('\n','\\\\')
    description = obj.description.replace('\n','\\\\')
    killchain = createKillChain(arrayTTP)
    write(title, author, description, groups, TTP, iocs, killchain)
    compile()


if __name__ == '__main__':
    obj = {
        "groups": [
            "APT-C-36",
            "APT18"
        ],
        "iocs": [
            "IP: 192.1.1.1",
            "Domain: www.as.es",
            "Hash: asn48rj32owdcm03eji2okdqwdwex"
        ],
        "subtechniques": [
            "TA0006 Credential Access T1003 OS Credential Dumping T1003.001 LSASS Memory",
            "TA0006 Credential Access T1003 OS Credential Dumping T1003.005 Cached Domain Credentials",
            "TA0006 Credential Access T1111 Multi-Factor Authentication Interception No sub-techniques",
            "TA0040 Impact T1490 Inhibit System Recovery No sub-techniques"
        ]
    }

    clean()
    groups = createGroups(obj["groups"])
    TTP = createTTP(obj["subtechniques"])
    iocs = createIocs(obj["iocs"])
    write(groups, TTP, iocs)
    compile()