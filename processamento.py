import re
from datetime import datetime
from collections import defaultdict

def ler_arquivo(nome_arquivo):
    try:
        with open(nome_arquivo, 'r') as arquivo:
            return arquivo.readlines()
    except FileNotFoundError:
        print("Arquivo não encontrado")
        return None
    
# Função de extração das informações
def extrai_info_log(lista_linhas):
    info_logs = {}
    for i in range(len(lista_linhas)):
        dic_log = {}
        info = lista_linhas[i].split()
        dic_log['ip'] = info[0]
        dic_log['id_cliente'] = info[1]
        dic_log['usuario'] = info[2]
        dic_log['data'] = info[3].replace('[','')
        dic_log['requisicao'] = info[5] + " " + info[6] + " " + info[7]
        dic_log['status'] = info[8]
        dic_log['bytes_resposta'] = info[9]
        dic_log['referenciador'] = info[10]
        dic_log['navegador'] = info[11].replace('"','')

        info_logs[i] = dic_log

    return info_logs

#Ataque XSS
def ataque_xss(logs_post):
    logs_suspeitos = defaultdict(list)
    padroes_suspeitos = [
        '<script>', 'onload=', 'eval(', 
        '<iframe>', 'javascript:', '<embed>', '<object>', '<applet>',
        'onclick=', 'onmouseover=', 'onerror=',
        '%3Cscript%3E', '%3Ciframe%3E',
        'alert(', 'document.cookie', 'window.location', 'innerHTML',
        '"></script>', '<img src="x" onerror=', '"><svg onload=',
        '{{7*7}}', '${7*7}', 
        'base64', '\\u'
    ]

    for key, value in logs_post.items():
        for padrao in padroes_suspeitos:
            if padrao in value['requisicao'].lower():
                motivo = f"Padrão suspeito: {padrao}"
                value['motivo'] = [motivo]
                logs_suspeitos[value['ip']].append({'requisicao': value['requisicao'], 'motivo': value['motivo'], 'data': value['data']})
                break
    return logs_suspeitos

#SQL Injection
def sql_injection(logs_post):
    logs_suspeitos = defaultdict(list)
    padroes_suspeitos = [
        'select', 'union', 'insert', 'update', 'delete', 'drop', 'alter', 'create',
        'truncate', 'exec', 'grant', 'revoke',
        "' or '1'='1", "--", "#", ";", "/*", "*/",
        "char(", "concat(", "load_file(", "sleep(",
        "information_schema", "table_schema", "column_name",
        "'=", "like '%'", "and 1=1"
    ]
    
    for key, value in logs_post.items():
        for padrao in padroes_suspeitos:
            if padrao in value['requisicao'].lower():
                motivo = f"Padrão suspeito: {padrao}"
                value['motivo'] = [motivo]
                logs_suspeitos[value['ip']].append({'requisicao': value['requisicao'], 'motivo': value['motivo'], 'data': value['data']})
                break 
    return logs_suspeitos

#DDos
def ddos(logs_post, intervalo_segundos=10, limite_requisicoes=5):
    logs_suspeitos = defaultdict(list)
    ip_atividades = {}

    for key, value in logs_post.items():
        ip = value['ip']
        data = datetime.strptime(value['data'], '%d/%b/%Y:%H:%M:%S')

        if ip not in ip_atividades:
            ip_atividades[ip] = []
        ip_atividades[ip].append((key, data))

    for ip, acessos in ip_atividades.items():
        acessos.sort(key=lambda x: x[1])  

        for i in range(len(acessos) - limite_requisicoes + 1):
            inicio = acessos[i][1]
            fim = acessos[i + limite_requisicoes - 1][1]
            delta = (fim - inicio).total_seconds()

            if delta <= intervalo_segundos:
                
                for j in range(i, i + limite_requisicoes):
                    key = acessos[j][0]
                    motivo = f"Alta frequência de acessos: {limite_requisicoes} requisições em {delta} segundos"
                    logs_post[key]['motivo'] = [motivo]
                    logs_suspeitos[logs_post[key]['ip']].append({'requisicao': logs_post[key]['requisicao'], 'motivo': logs_post[key]['motivo'], 'data': logs_post[key]['data']})
                break

    return logs_suspeitos


#Notificar que talvez haja uma resposta positiva pra um ataque
def resposta_positiva_ataque(logs_post):
    logs_suspeitos = defaultdict(list)
    requisicoes_analisadas = {}

    for key, value in logs_post.items():
        requisicao = value['requisicao']
        bytes_resposta = int(value['bytes_resposta'])

        if requisicao not in requisicoes_analisadas:
            requisicoes_analisadas[requisicao] = []
        else:
            tamanhos = requisicoes_analisadas[requisicao]
            if bytes_resposta not in tamanhos:
                motivo = f"Mudança no tamanho da resposta para a mesma requisição: {requisicao}"
                value['motivo'] = [motivo]
                logs_suspeitos[value['ip']].append({'requisicao': value['requisicao'], 'motivo': value['motivo'], 'data': value['data']})
        requisicoes_analisadas[requisicao].append(bytes_resposta)

    return logs_suspeitos

#Navegadores Suspeitos
def navegador_suspeito(logs_post): 
    logs_suspeitos = defaultdict(list)
    navegador_nao_suspeitos=['Mozilla', 'Chrome', 'Safari', 'Opera', 'Edge', 'Trident', 'Microsoft']

    for key, value in logs_post.items():
        #if value['referenciador'] == '"-"':
        #    motivo = "Referenciador ausente ou suspeito"
        #    value['motivo'] = [motivo]
        #    logs_suspeitos[key] = value
        if value['navegador'].split('/')[0] not in navegador_nao_suspeitos:
            motivo = f"Navegador suspeito ou desconhecido: {value['navegador'].split('/')[0]}"
            value['motivo'] = [motivo]
            logs_suspeitos[value['ip']].append({'requisicao': value['requisicao'], 'motivo': value['motivo'], 'data': value['data']})

    return logs_suspeitos

#Directory Transversal + LFI
def directory_transversal_e_lfi(info_logs):
    caminhos_suspeitos = [
        '/etc/passwd',
        'etc/shadow',
        '/proc/self/environ', 
        '/var/www/html',
        '/shell',
        '/index.php.bak',
        '/logs',
        '/robots.txt',
        '/wpad.dat',
        '/etc/',
        '..',
        '?file=', 
        '?path=', 
        '?cmd=', 
        '?exec=',
        '?debug=', 
        '?action=',
        '?page=',
        '.php',
        '.sh', 
        '.exe'
    ]

    lfi_suspeitas = defaultdict(list)
    directory_transversal_suspeitas = defaultdict(list)

    for key, log in info_logs.items():
        for caminhos in caminhos_suspeitos:
            if caminhos in log['requisicao']:
                log['motivo'] = f"O caminho {caminhos} foi encontrado"
                if 'GET' in log['requisicao']:
                    directory_transversal_suspeitas[log['ip']].append({'requisicao': log['requisicao'], 'motivo': log['motivo'], 'data': log['data']})
                else:
                    lfi_suspeitas[log['ip']].append({'requisicao': log['requisicao'], 'motivo': log['motivo'], 'data': log['data']})

    return lfi_suspeitas, directory_transversal_suspeitas

def identifica_caminhos_suspeitos(info_logs):
    # Lista de caminhos considerados suspeitos
    caminhos_suspeitos = [
        '/admin',
        '/administrator',
        'admin-ajax.php', 
        '/console',
        '/controlpanel',
        '/login',
        '/dashboard',
        '/dbadmin',
        '/server-status',
        '/private',
        '/phpmyadmin',

        'config',
        'config.php',
        '/admin.php',
        'backup',
        'backup.sql',
        'debug',
        '.env',
        'settings.php',
        'db_backup.sql',
        'db_dump.sql',
        'htaccess',
        'htpasswd'

        'wp-login',
        'wp-admin',
        'xmlrpc.php',
        'wp-content',
        'wp-content/plugins',
        'wp-content/themes',
        'wp-content/uploads',
        'wp-includes',
        'wp-config.php', 
        'wp-json/',

        '/phpmyadmin',
        '/server-status', 
        '/actuator/health',

        '/debug', 
        '/shell', 
        '/cmd', 
        'cgi-bin/', 
        'shell.php',
        'eval-stdin.php',

        '/api/v1/', 
        '/graphql',
        '/admin/api/'

    ]

    requisicoes_suspeitas = defaultdict(list)

    for key, log in info_logs.items():
        for caminho in caminhos_suspeitos:
            if caminho in log['requisicao']:
                log['motivo'] = f"O caminho suspeito {caminho} foi encontrado"
                requisicoes_suspeitas[log['ip']].append({'requisicao': log['requisicao'], 'motivo': log['motivo'], 'data': log['data']})
                break  # Parar após encontrar o primeiro caminho suspeito

    return requisicoes_suspeitas

def produzindo_estatisticas (dados_ataque):
    ip_por_numero_requisicao = defaultdict(dict)

    for key, value in dados_ataque.items():
        for ip in sorted(value['ips'].keys(), key=lambda k: len(value['ips'][k]), reverse=True):
            if len(ip_por_numero_requisicao[key]) >= 5:
                break
            ip_por_numero_requisicao[key][ip] = len(value['ips'][ip])

    return ip_por_numero_requisicao

def brute_force_senha(dados_ataque, intervalo_segundos=10, limite_requisicoes=5):
    # Definir caminhos relacionados a login/senha
    caminhos_login = [
        '/login', '/signin', '/auth', '/authentication', '/user/login',
        '/admin/login', '/api/login', '/wp-login.php', '/dashboard/auth'
    ]

    logs_post = {}
    for i in range(len(dados_ataque)):
        if 'POST' in dados_ataque[i]['requisicao'] or 'PUT' in dados_ataque[i]['requisicao'] or 'PATCH' in dados_ataque[i]['requisicao'] or 'DELETE' in dados_ataque[i]['requisicao']:
            for caminho in caminhos_login:
                if caminho in dados_ataque[i]['requisicao']:
                    logs_post[i] = {**dados_ataque[i], 'caminho': caminho}
                    break

    logs_suspeitos = defaultdict(list)
    ip_atividades = {}

    for key, value in logs_post.items():
        ip = value['ip']
        data = datetime.strptime(value['data'], '%d/%b/%Y:%H:%M:%S')

        if ip not in ip_atividades:
            ip_atividades[ip] = []
        ip_atividades[ip].append((key, data))

    for ip, acessos in ip_atividades.items():
        acessos.sort(key=lambda x: x[1]) 

        for i in range(len(acessos) - limite_requisicoes + 1):
            inicio = acessos[i][1]
            fim = acessos[i + limite_requisicoes - 1][1]
            delta = (fim - inicio).total_seconds()

            if delta <= intervalo_segundos:
                caminho_suspeito = logs_post[acessos[i][0]]['caminho']
                for j in range(i, i + limite_requisicoes):
                    key = acessos[j][0]
                    motivo = f"Tentativa de brute force detectada: {limite_requisicoes} requisições em {delta} segundos para {caminho_suspeito}"
                    logs_post[key]['motivo'] = [motivo]
                    logs_suspeitos[logs_post[key]['ip']].append({
                        'requisicao': logs_post[key]['requisicao'],
                        'motivo': logs_post[key]['motivo'],
                        'data': logs_post[key]['data']
                    })
                break

    return logs_suspeitos




    

def processando_dados(file_path):
    linhas_log = ler_arquivo(file_path)
    #Separa em dicionário nas categorias: IP, id_cliente, usuario, data, requisicao, status, bytes_resposta, referenciador, navegador
    dicionario_log = extrai_info_log(linhas_log)

    data_ataque = {
        "xss" : {
            "title": "Ataque XSS",
            "ips" : ataque_xss(dicionario_log)
        },
        "sql injection" : {
            "title": "Injeção SQL",
            "ips" : sql_injection(dicionario_log)
        },
        "ddos" : {
            "title": "Ataque DDoS",
            "ips": ddos(dicionario_log)
        },
        "resposta positiva": {
            "title": "Possível resposta positiva para um ataque (Detecção de mudança de bytes)",
            "ips": resposta_positiva_ataque(dicionario_log)
        },
        "navegador suspeito": {
            "title": "Navegador Suspeito",
            "ips": navegador_suspeito(dicionario_log)
        },
        "lfi": {
            "title": "Suspeita de LFI",
            "ips": directory_transversal_e_lfi(dicionario_log)[0]
        },
        "directory transversal": {
            "title": "Directory Transversal",
            "ips": directory_transversal_e_lfi(dicionario_log)[1]
        },
        "caminhos suspeitos": {
            "title": "Caminhos Suspeitos Identificados",
            "ips": identifica_caminhos_suspeitos(dicionario_log)
        },
        "brute force": {
            "title": "Brute Force",
            "ips": brute_force_senha(dicionario_log)
        }

    }

    print(produzindo_estatisticas(data_ataque))

    return data_ataque

#processando_dados('access.log')